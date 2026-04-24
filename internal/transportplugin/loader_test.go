package transportplugin_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"go.uber.org/zap/zaptest"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/transportplugin"
)

// TestLoader_EndToEndEcho builds the transport-echo plugin, drops it
// into a temp dir under the correct filename convention, spawns it
// through the Loader, dispatches one request, and asserts the
// round-trip body. Covers: Discover, Load, Dispatch, Close.
//
// The test builds the plugin binary inside the temp dir rather than
// shelling out to a pre-built one. That keeps the test hermetic —
// CI doesn't need a two-step build — but does require `go` on PATH.
func TestLoader_EndToEndEcho(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode skips subprocess-heavy plugin test")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not on PATH; skipping")
	}

	dir := t.TempDir()
	binaryPath := filepath.Join(dir, "yggdrasil-transport-echo")

	build := exec.Command("go", "build", "-o", binaryPath, "../../cmd/transport-echo")
	build.Stdout = os.Stdout
	build.Stderr = os.Stderr
	if err := build.Run(); err != nil {
		t.Fatalf("go build transport-echo: %v", err)
	}

	logger := zaptest.NewLogger(t)
	loader := transportplugin.NewLoader(dir, logger)
	defer loader.Close()

	names, err := loader.Discover()
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	if len(names) != 1 || names[0] != "echo" {
		t.Fatalf("Discover = %#v, want [echo]", names)
	}

	loaded, err := loader.Load("echo")
	if err != nil {
		t.Fatalf("Load echo: %v", err)
	}
	if loaded.Name != "echo" {
		t.Errorf("loaded.Name = %q, want echo", loaded.Name)
	}

	reply, err := loaded.Transport.Dispatch(transportplugin.DispatchRequest{
		Endpoint:      "demo",
		Body:          []byte(`{"hello":"world"}`),
		ContentType:   "application/json",
		CorrelationID: "cid-123",
	})
	if err != nil {
		t.Fatalf("Dispatch: %v", err)
	}
	if !strings.Contains(string(reply.Body), `"echo":true`) {
		t.Errorf("reply body does not look like an echo: %s", reply.Body)
	}
	if !strings.Contains(string(reply.Body), `"endpoint":"demo"`) {
		t.Errorf("reply body does not carry endpoint: %s", reply.Body)
	}
	if reply.Headers["x-echo-correlation"] != "cid-123" {
		t.Errorf("correlation header = %q, want cid-123", reply.Headers["x-echo-correlation"])
	}
}

// TestLoader_DiscoverEmptyDir exercises the zero-plugin deployment
// path. A Loader pointed at an empty/missing dir should return an
// empty slice, NOT an error — this is the default for any yggdrasil
// install that hasn't opted into plugins yet.
func TestLoader_DiscoverEmptyDir(t *testing.T) {
	loader := transportplugin.NewLoader(t.TempDir(), zaptest.NewLogger(t))
	names, err := loader.Discover()
	if err != nil {
		t.Fatalf("Discover on empty dir: %v", err)
	}
	if len(names) != 0 {
		t.Errorf("Discover on empty dir = %#v, want []", names)
	}

	loader = transportplugin.NewLoader("/this/path/definitely/does/not/exist", zaptest.NewLogger(t))
	names, err = loader.Discover()
	if err != nil {
		t.Fatalf("Discover on missing dir: %v", err)
	}
	if len(names) != 0 {
		t.Errorf("Discover on missing dir = %#v, want []", names)
	}
}

// TestLoader_LoadUnknownPluginReturnsErrPluginNotFound keeps the
// sentinel error stable for callers that want to differentiate
// "plugin missing" from other errors (e.g. gracefully degrade when a
// feature asks for a plugin that wasn't installed).
func TestLoader_LoadUnknownPluginReturnsErrPluginNotFound(t *testing.T) {
	loader := transportplugin.NewLoader(t.TempDir(), zaptest.NewLogger(t))
	_, err := loader.Load("nonexistent")
	if err == nil {
		t.Fatal("expected error loading nonexistent plugin")
	}
	if !errorContains(err, "transport plugin not found") {
		t.Errorf("error = %v, want one derived from ErrPluginNotFound", err)
	}
}

func errorContains(err error, needle string) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), needle)
}
