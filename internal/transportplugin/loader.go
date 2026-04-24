package transportplugin

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	"github.com/hashicorp/go-plugin"
	"go.uber.org/zap"
)

// LoadedPlugin is a spawned transport plugin the core can call. The
// owning Loader is responsible for its lifecycle — callers just use
// the embedded Transport and don't close the client directly.
type LoadedPlugin struct {
	Name      string
	Path      string
	Transport Transport

	client *plugin.Client
}

// Loader discovers plugin binaries in a directory and spawns them on
// demand. Discovery convention: any file matching "yggdrasil-transport-*"
// inside the directory is treated as a plugin; its basename minus the
// prefix is the default short name (e.g. yggdrasil-transport-kafka →
// "kafka"). The plugin itself self-reports via Name() on first call.
type Loader struct {
	dir    string
	logger *zap.Logger

	mu      sync.Mutex
	loaded  map[string]*LoadedPlugin // keyed by resolved short name
}

// NewLoader constructs a Loader. dir may be empty, in which case
// Discover returns an empty slice and Load returns ErrPluginNotFound
// for any name — this is deliberate so a deployment without plugins
// operates normally.
func NewLoader(dir string, logger *zap.Logger) *Loader {
	return &Loader{
		dir:    strings.TrimSpace(dir),
		logger: logger,
		loaded: map[string]*LoadedPlugin{},
	}
}

// ErrPluginNotFound is returned when Discover finds no matching binary
// for the requested name.
var ErrPluginNotFound = errors.New("transport plugin not found")

// pluginFilenamePrefix is the convention Discover uses to identify
// plugin binaries. Matching against a prefix is enough — we don't
// need a registry file — and keeps plugins copyable into the dir
// with no additional wiring.
const pluginFilenamePrefix = "yggdrasil-transport-"

// Discover walks the plugin directory and returns basenames of the
// plugins present (short names without the "yggdrasil-transport-"
// prefix). Used for logging at startup + the `yggdrasil status`
// command to show which transports are available.
func (l *Loader) Discover() ([]string, error) {
	if l.dir == "" {
		return nil, nil
	}
	entries, err := os.ReadDir(l.dir)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, fmt.Errorf("read plugin dir %s: %w", l.dir, err)
	}
	var names []string
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		base := entry.Name()
		if !strings.HasPrefix(base, pluginFilenamePrefix) {
			continue
		}
		short := strings.TrimPrefix(base, pluginFilenamePrefix)
		if short == "" {
			continue
		}
		names = append(names, short)
	}
	sort.Strings(names)
	return names, nil
}

// Load spawns (or returns the cached) plugin with the given short
// name. Subsequent calls with the same name return the same running
// subprocess — Close shuts them all down.
func (l *Loader) Load(name string) (*LoadedPlugin, error) {
	name = strings.TrimSpace(name)
	if name == "" {
		return nil, errors.New("transportplugin: Load requires a non-empty name")
	}

	l.mu.Lock()
	defer l.mu.Unlock()
	if existing, ok := l.loaded[name]; ok {
		return existing, nil
	}

	path := filepath.Join(l.dir, pluginFilenamePrefix+name)
	info, err := os.Stat(path)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, fmt.Errorf("%w: %s", ErrPluginNotFound, name)
		}
		return nil, fmt.Errorf("stat %s: %w", path, err)
	}
	if info.IsDir() || info.Mode()&0o111 == 0 {
		return nil, fmt.Errorf("transport plugin %s at %s is not an executable file", name, path)
	}

	client := plugin.NewClient(&plugin.ClientConfig{
		HandshakeConfig: Handshake,
		Plugins:         PluginMap(nil),
		Cmd:             exec.Command(path),
		Logger:          pluginHCLogger(l.logger, name),
	})
	rpcClient, err := client.Client()
	if err != nil {
		client.Kill()
		return nil, fmt.Errorf("connect to transport plugin %s: %w", name, err)
	}
	raw, err := rpcClient.Dispense("transport")
	if err != nil {
		client.Kill()
		return nil, fmt.Errorf("dispense transport from %s: %w", name, err)
	}
	transport, ok := raw.(Transport)
	if !ok {
		client.Kill()
		return nil, fmt.Errorf("plugin %s did not expose a Transport (got %T)", name, raw)
	}

	reported, err := transport.Name()
	if err != nil {
		client.Kill()
		return nil, fmt.Errorf("transport plugin %s Name() failed: %w", name, err)
	}

	loaded := &LoadedPlugin{
		Name:      reported,
		Path:      path,
		Transport: transport,
		client:    client,
	}
	l.loaded[name] = loaded
	l.logger.Info("transport plugin loaded",
		zap.String("name", name),
		zap.String("reported_name", reported),
		zap.String("path", path),
	)
	return loaded, nil
}

// Close tears down every spawned plugin. Safe to call multiple times.
// go-plugin already SIGKILLs on Kill, so this is primarily about
// giving plugins a chance to flush state via their Close method.
func (l *Loader) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	var errs []error
	for name, p := range l.loaded {
		if err := p.Transport.Close(); err != nil {
			errs = append(errs, fmt.Errorf("%s close: %w", name, err))
		}
		p.client.Kill()
	}
	l.loaded = map[string]*LoadedPlugin{}
	return errors.Join(errs...)
}
