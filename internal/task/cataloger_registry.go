package task

import (
	"fmt"
	"sort"
	"sync"

	"github.com/anchore/syft/syft/pkg"
)

// CatalogerEntry represents a registered external cataloger with its configuration
type CatalogerEntry struct {
	Name             string                                      // unique cataloger name
	CatalogerFactory func(CatalogingFactoryConfig) pkg.Cataloger // factory function for cataloger
	SimpleCataloger  func() pkg.Cataloger                        // simple factory (no config)
	Tags             []string                                    // tags for selection
	Priority         int                                         // higher priority = processed first
	IsSimple         bool                                        // whether to use simple factory
}

// CatalogerRegistry manages external cataloger registration
type CatalogerRegistry struct {
	mu      sync.RWMutex
	entries []CatalogerEntry
}

// DefaultCatalogerRegistry is the global registry for external catalogers
var DefaultCatalogerRegistry = NewCatalogerRegistry()

// NewCatalogerRegistry creates a new cataloger registry
func NewCatalogerRegistry() *CatalogerRegistry {
	return &CatalogerRegistry{
		entries: make([]CatalogerEntry, 0),
	}
}

// RegisterCataloger registers an external cataloger with configuration support.
// The catalogerFactory function receives CatalogingFactoryConfig and returns a configured cataloger.
// Higher priority catalogers are processed first (default built-ins have priority 0).
func (r *CatalogerRegistry) RegisterCataloger(name string, catalogerFactory func(CatalogingFactoryConfig) pkg.Cataloger, priority int, tags ...string) error {
	if catalogerFactory == nil {
		return fmt.Errorf("cataloger factory cannot be nil")
	}
	if name == "" {
		return fmt.Errorf("cataloger name cannot be empty")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Check for duplicate names
	for _, entry := range r.entries {
		if entry.Name == name {
			return fmt.Errorf("cataloger with name %q already registered", name)
		}
	}

	r.entries = append(r.entries, CatalogerEntry{
		Name:             name,
		CatalogerFactory: catalogerFactory,
		Tags:             tags,
		Priority:         priority,
		IsSimple:         false,
	})

	// Sort by priority (highest first), then by name for deterministic order
	sort.Slice(r.entries, func(i, j int) bool {
		if r.entries[i].Priority != r.entries[j].Priority {
			return r.entries[i].Priority > r.entries[j].Priority
		}
		return r.entries[i].Name < r.entries[j].Name
	})

	return nil
}

// RegisterSimpleCataloger registers an external cataloger without configuration support.
// The catalogerFactory function takes no parameters and returns a cataloger.
// This is useful for simple catalogers that don't need configuration.
func (r *CatalogerRegistry) RegisterSimpleCataloger(name string, catalogerFactory func() pkg.Cataloger, priority int, tags ...string) error {
	if catalogerFactory == nil {
		return fmt.Errorf("cataloger factory cannot be nil")
	}
	if name == "" {
		return fmt.Errorf("cataloger name cannot be empty")
	}

	r.mu.Lock()
	defer r.mu.Unlock()

	// Check for duplicate names
	for _, entry := range r.entries {
		if entry.Name == name {
			return fmt.Errorf("cataloger with name %q already registered", name)
		}
	}

	r.entries = append(r.entries, CatalogerEntry{
		Name:            name,
		SimpleCataloger: catalogerFactory,
		Tags:            tags,
		Priority:        priority,
		IsSimple:        true,
	})

	// Sort by priority (highest first), then by name for deterministic order
	sort.Slice(r.entries, func(i, j int) bool {
		if r.entries[i].Priority != r.entries[j].Priority {
			return r.entries[i].Priority > r.entries[j].Priority
		}
		return r.entries[i].Name < r.entries[j].Name
	})

	return nil
}

// GetFactories returns task factories for all registered catalogers (thread-safe)
func (r *CatalogerRegistry) GetFactories() Factories {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var factories Factories
	for _, entry := range r.entries {
		if entry.IsSimple {
			factories = append(factories, newSimplePackageTaskFactory(entry.SimpleCataloger, entry.Tags...))
		} else {
			factories = append(factories, newPackageTaskFactory(entry.CatalogerFactory, entry.Tags...))
		}
	}

	return factories
}

// GetEntries returns a copy of all registered cataloger entries (thread-safe)
func (r *CatalogerRegistry) GetEntries() []CatalogerEntry {
	r.mu.RLock()
	defer r.mu.RUnlock()

	// Return a copy to prevent external mutation
	result := make([]CatalogerEntry, len(r.entries))
	copy(result, r.entries)
	return result
}

// ListCatalogers returns the names of all registered catalogers
func (r *CatalogerRegistry) ListCatalogers() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var names []string
	for _, entry := range r.entries {
		names = append(names, entry.Name)
	}
	return names
}

// HasCataloger checks if a cataloger with the given name is registered
func (r *CatalogerRegistry) HasCataloger(name string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for _, entry := range r.entries {
		if entry.Name == name {
			return true
		}
	}
	return false
}

// Package-level convenience functions for the default registry

// RegisterCataloger registers an external cataloger with the default registry.
// The catalogerFactory function receives CatalogingFactoryConfig and returns a configured cataloger.
func RegisterCataloger(name string, catalogerFactory func(CatalogingFactoryConfig) pkg.Cataloger, priority int, tags ...string) error {
	return DefaultCatalogerRegistry.RegisterCataloger(name, catalogerFactory, priority, tags...)
}

// RegisterSimpleCataloger registers an external cataloger with the default registry.
// The catalogerFactory function takes no parameters and returns a cataloger.
func RegisterSimpleCataloger(name string, catalogerFactory func() pkg.Cataloger, priority int, tags ...string) error {
	return DefaultCatalogerRegistry.RegisterSimpleCataloger(name, catalogerFactory, priority, tags...)
}

// ListRegisteredCatalogers returns the names of all registered external catalogers
func ListRegisteredCatalogers() []string {
	return DefaultCatalogerRegistry.ListCatalogers()
}

// HasRegisteredCataloger checks if a cataloger with the given name is registered
func HasRegisteredCataloger(name string) bool {
	return DefaultCatalogerRegistry.HasCataloger(name)
}
