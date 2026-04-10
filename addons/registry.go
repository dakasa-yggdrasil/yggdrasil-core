package addons

import (
	"context"
	"sort"
	"sync"

	"github.com/dakasa-yggdrasil/yggdrasil-core/internal/runtime"
)

// Bootstrap initializes one optional addon.
type Bootstrap func(context.Context, *runtime.ServiceApp) error

type registeredAddon struct {
	name     string
	priority int
	run      Bootstrap
}

var (
	mu       sync.RWMutex
	registry []registeredAddon
)

// Register adds an addon bootstrap to the runtime registry.
// Lower priorities execute first.
func Register(name string, run Bootstrap, priority ...int) {
	value := 100
	if len(priority) > 0 {
		value = priority[0]
	}

	mu.Lock()
	defer mu.Unlock()
	registry = append(registry, registeredAddon{name: name, priority: value, run: run})
}

// Apply executes every registered addon bootstrap.
func Apply(ctx context.Context, app *runtime.ServiceApp) error {
	mu.RLock()
	entries := make([]registeredAddon, len(registry))
	copy(entries, registry)
	mu.RUnlock()

	sort.Slice(entries, func(i, j int) bool {
		if entries[i].priority == entries[j].priority {
			return entries[i].name < entries[j].name
		}
		return entries[i].priority < entries[j].priority
	})

	for _, entry := range entries {
		if err := entry.run(ctx, app); err != nil {
			return err
		}
	}

	return nil
}

// Names returns the registered addon names.
func Names() []string {
	mu.RLock()
	defer mu.RUnlock()

	names := make([]string, 0, len(registry))
	for _, entry := range registry {
		names = append(names, entry.name)
	}
	sort.Strings(names)
	return names
}
