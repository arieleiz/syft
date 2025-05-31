package task

import (
	"context"
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/artifact"
	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/pkg"
)

// Mock cataloger for testing
type mockCataloger struct {
	name string
}

func (m *mockCataloger) Name() string {
	return m.name
}

func (m *mockCataloger) Catalog(ctx context.Context, resolver file.Resolver) ([]pkg.Package, []artifact.Relationship, error) {
	return []pkg.Package{
		{
			Name:    fmt.Sprintf("package-from-%s", m.name),
			Version: "1.0.0",
			Type:    pkg.BinaryPkg,
			FoundBy: m.name,
		},
	}, nil, nil
}

func TestCatalogerRegistry_RegisterCataloger(t *testing.T) {
	tests := []struct {
		name          string
		catalogerName string
		factory       func(CatalogingFactoryConfig) pkg.Cataloger
		priority      int
		tags          []string
		expectError   bool
	}{
		{
			name:          "valid cataloger registration",
			catalogerName: "test-cataloger",
			factory: func(cfg CatalogingFactoryConfig) pkg.Cataloger {
				return &mockCataloger{name: "test-cataloger"}
			},
			priority: 10,
			tags:     []string{"test", "mock"},
		},
		{
			name:          "nil factory should error",
			catalogerName: "nil-factory",
			factory:       nil,
			priority:      10,
			tags:          []string{"test"},
			expectError:   true,
		},
		{
			name:          "empty name should error",
			catalogerName: "",
			factory: func(cfg CatalogingFactoryConfig) pkg.Cataloger {
				return &mockCataloger{name: "unnamed"}
			},
			priority:    10,
			tags:        []string{"test"},
			expectError: true,
		},
		{
			name:          "negative priority is allowed",
			catalogerName: "low-priority",
			factory: func(cfg CatalogingFactoryConfig) pkg.Cataloger {
				return &mockCataloger{name: "low-priority"}
			},
			priority: -100,
			tags:     []string{"test"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := NewCatalogerRegistry()

			err := registry.RegisterCataloger(tt.catalogerName, tt.factory, tt.priority, tt.tags...)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)

			// Verify cataloger was registered
			entries := registry.GetEntries()
			found := false
			for _, entry := range entries {
				if entry.Name == tt.catalogerName && entry.Priority == tt.priority {
					assert.Equal(t, tt.tags, entry.Tags)
					assert.False(t, entry.IsSimple)
					assert.NotNil(t, entry.CatalogerFactory)
					found = true
					break
				}
			}
			assert.True(t, found, "cataloger should be registered")
		})
	}
}

func TestCatalogerRegistry_RegisterSimpleCataloger(t *testing.T) {
	tests := []struct {
		name          string
		catalogerName string
		factory       func() pkg.Cataloger
		priority      int
		tags          []string
		expectError   bool
	}{
		{
			name:          "valid simple cataloger registration",
			catalogerName: "simple-test",
			factory: func() pkg.Cataloger {
				return &mockCataloger{name: "simple-test"}
			},
			priority: 5,
			tags:     []string{"simple", "test"},
		},
		{
			name:          "nil simple factory should error",
			catalogerName: "nil-simple",
			factory:       nil,
			priority:      5,
			tags:          []string{"test"},
			expectError:   true,
		},
		{
			name:          "empty name should error",
			catalogerName: "",
			factory: func() pkg.Cataloger {
				return &mockCataloger{name: "unnamed"}
			},
			priority:    5,
			tags:        []string{"test"},
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := NewCatalogerRegistry()

			err := registry.RegisterSimpleCataloger(tt.catalogerName, tt.factory, tt.priority, tt.tags...)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)

			// Verify cataloger was registered
			entries := registry.GetEntries()
			found := false
			for _, entry := range entries {
				if entry.Name == tt.catalogerName && entry.Priority == tt.priority {
					assert.Equal(t, tt.tags, entry.Tags)
					assert.True(t, entry.IsSimple)
					assert.NotNil(t, entry.SimpleCataloger)
					found = true
					break
				}
			}
			assert.True(t, found, "simple cataloger should be registered")
		})
	}
}

func TestCatalogerRegistry_DuplicateNames(t *testing.T) {
	registry := NewCatalogerRegistry()

	factory := func() pkg.Cataloger {
		return &mockCataloger{name: "duplicate"}
	}

	// Register first cataloger
	err := registry.RegisterSimpleCataloger("duplicate", factory, 10, "test")
	require.NoError(t, err)

	// Try to register with same name - should error
	err = registry.RegisterSimpleCataloger("duplicate", factory, 20, "test2")
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "already registered")
}

func TestCatalogerRegistry_PriorityOrdering(t *testing.T) {
	registry := NewCatalogerRegistry()

	// Register catalogers with different priorities
	err := registry.RegisterSimpleCataloger("low", func() pkg.Cataloger {
		return &mockCataloger{name: "low"}
	}, 1, "test")
	require.NoError(t, err)

	err = registry.RegisterSimpleCataloger("high", func() pkg.Cataloger {
		return &mockCataloger{name: "high"}
	}, 10, "test")
	require.NoError(t, err)

	err = registry.RegisterSimpleCataloger("medium", func() pkg.Cataloger {
		return &mockCataloger{name: "medium"}
	}, 5, "test")
	require.NoError(t, err)

	entries := registry.GetEntries()
	require.Len(t, entries, 3)

	// Should be ordered by priority (highest first)
	assert.Equal(t, "high", entries[0].Name)
	assert.Equal(t, 10, entries[0].Priority)

	assert.Equal(t, "medium", entries[1].Name)
	assert.Equal(t, 5, entries[1].Priority)

	assert.Equal(t, "low", entries[2].Name)
	assert.Equal(t, 1, entries[2].Priority)
}

func TestCatalogerRegistry_GetFactories(t *testing.T) {
	registry := NewCatalogerRegistry()

	// Register both simple and complex catalogers
	err := registry.RegisterSimpleCataloger("simple", func() pkg.Cataloger {
		return &mockCataloger{name: "simple"}
	}, 10, "simple", "test")
	require.NoError(t, err)

	err = registry.RegisterCataloger("complex", func(cfg CatalogingFactoryConfig) pkg.Cataloger {
		return &mockCataloger{name: "complex"}
	}, 5, "complex", "test")
	require.NoError(t, err)

	factories := registry.GetFactories()
	assert.Len(t, factories, 2)

	// Test that factories can create tasks
	cfg := CatalogingFactoryConfig{} // Empty config for testing
	tasks, err := factories.Tasks(cfg)
	require.NoError(t, err)
	assert.Len(t, tasks, 2)

	// Verify task names match cataloger names
	taskNames := make(map[string]bool)
	for _, task := range tasks {
		taskNames[task.Name()] = true
	}
	assert.True(t, taskNames["simple"])
	assert.True(t, taskNames["complex"])
}

func TestCatalogerRegistry_ThreadSafety(t *testing.T) {
	registry := NewCatalogerRegistry()

	// Get initial state
	entries1 := registry.GetEntries()
	assert.Len(t, entries1, 0)

	// Register a cataloger
	err := registry.RegisterSimpleCataloger("thread-test", func() pkg.Cataloger {
		return &mockCataloger{name: "thread-test"}
	}, 10, "test")
	require.NoError(t, err)

	// Original copy should be unchanged (defensive copy)
	assert.Len(t, entries1, 0)

	// New copy should have the cataloger
	entries2 := registry.GetEntries()
	assert.Len(t, entries2, 1)
	assert.Equal(t, "thread-test", entries2[0].Name)
}

func TestCatalogerRegistry_HelperMethods(t *testing.T) {
	registry := NewCatalogerRegistry()

	// Test with empty registry
	assert.False(t, registry.HasCataloger("nonexistent"))
	assert.Empty(t, registry.ListCatalogers())

	// Register some catalogers
	err := registry.RegisterSimpleCataloger("test1", func() pkg.Cataloger {
		return &mockCataloger{name: "test1"}
	}, 10, "test")
	require.NoError(t, err)

	err = registry.RegisterSimpleCataloger("test2", func() pkg.Cataloger {
		return &mockCataloger{name: "test2"}
	}, 5, "test")
	require.NoError(t, err)

	// Test HasCataloger
	assert.True(t, registry.HasCataloger("test1"))
	assert.True(t, registry.HasCataloger("test2"))
	assert.False(t, registry.HasCataloger("nonexistent"))

	// Test ListCatalogers (should be ordered by priority)
	names := registry.ListCatalogers()
	assert.Equal(t, []string{"test1", "test2"}, names) // test1 has higher priority
}

func TestDefaultRegistry_PackageLevelFunctions(t *testing.T) {
	// Clear any existing registrations by creating new registry
	originalRegistry := DefaultCatalogerRegistry
	DefaultCatalogerRegistry = NewCatalogerRegistry()
	defer func() {
		DefaultCatalogerRegistry = originalRegistry
	}()

	// Test package-level functions
	err := RegisterSimpleCataloger("package-test", func() pkg.Cataloger {
		return &mockCataloger{name: "package-test"}
	}, 10, "package", "test")
	require.NoError(t, err)

	assert.True(t, HasRegisteredCataloger("package-test"))
	assert.False(t, HasRegisteredCataloger("nonexistent"))

	names := ListRegisteredCatalogers()
	assert.Contains(t, names, "package-test")

	// Test RegisterCataloger (with config)
	err = RegisterCataloger("package-complex", func(cfg CatalogingFactoryConfig) pkg.Cataloger {
		return &mockCataloger{name: "package-complex"}
	}, 5, "package", "complex")
	require.NoError(t, err)

	assert.True(t, HasRegisteredCataloger("package-complex"))
	names = ListRegisteredCatalogers()
	assert.Contains(t, names, "package-complex")
}

func TestCatalogerRegistry_IntegrationWithTaskSystem(t *testing.T) {
	registry := NewCatalogerRegistry()

	// Register a cataloger
	err := registry.RegisterSimpleCataloger("integration-test", func() pkg.Cataloger {
		return &mockCataloger{name: "integration-test"}
	}, 100, "integration", "test", "mock")
	require.NoError(t, err)

	// Get factories and create tasks
	factories := registry.GetFactories()
	cfg := CatalogingFactoryConfig{}
	tasks, err := factories.Tasks(cfg)
	require.NoError(t, err)
	require.Len(t, tasks, 1)

	task := tasks[0]
	assert.Equal(t, "integration-test", task.Name())

	// Test that task has expected selectors
	if selector, ok := task.(Selector); ok {
		selectors := selector.Selectors()
		assert.Contains(t, selectors, "integration")
		assert.Contains(t, selectors, "test")
		assert.Contains(t, selectors, "mock")
		assert.Contains(t, selectors, "integration-test") // name should be included
	}
}