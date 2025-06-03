package main

import (
	"context"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/internal/task"
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
	return []pkg.Package{}, nil, nil
}

func TestExeCatalogerRegistration(t *testing.T) {
	// Clear registry for clean test
	originalRegistry := task.DefaultCatalogerRegistry
	task.DefaultCatalogerRegistry = task.NewCatalogerRegistry()
	defer func() {
		task.DefaultCatalogerRegistry = originalRegistry
	}()

	// Register the exe cataloger
	err := task.RegisterSimpleCataloger(
		"exe-version-cataloger",
		func() pkg.Cataloger {
			return &ExeVersionCataloger{}
		},
		100,
		"binary", "windows", "executable", "version",
	)
	require.NoError(t, err)

	// Verify registration
	assert.True(t, task.HasRegisteredCataloger("exe-version-cataloger"))

	catalogers := task.ListRegisteredCatalogers()
	assert.Contains(t, catalogers, "exe-version-cataloger")

	// Test that the cataloger is included in task factories
	factories := task.DefaultPackageTaskFactories()
	cfg := task.CatalogingFactoryConfig{}
	tasks, err := factories.Tasks(cfg)
	require.NoError(t, err)

	// Find our cataloger task
	var exeTask task.Task
	for _, tsk := range tasks {
		if tsk.Name() == "exe-version-cataloger" {
			exeTask = tsk
			break
		}
	}
	require.NotNil(t, exeTask, "exe cataloger task should be created")

	// Verify task has expected tags
	if selector, ok := exeTask.(task.Selector); ok {
		selectors := selector.Selectors()
		assert.Contains(t, selectors, "binary")
		assert.Contains(t, selectors, "windows")
		assert.Contains(t, selectors, "executable")
		assert.Contains(t, selectors, "version")
		assert.Contains(t, selectors, "exe-version-cataloger")
	}
}

func TestExeCatalogerPriority(t *testing.T) {
	// Clear registry for clean test
	originalRegistry := task.DefaultCatalogerRegistry
	task.DefaultCatalogerRegistry = task.NewCatalogerRegistry()
	defer func() {
		task.DefaultCatalogerRegistry = originalRegistry
	}()

	// Register multiple catalogers with different priorities
	err := task.RegisterSimpleCataloger("low-priority", func() pkg.Cataloger {
		return &mockCataloger{name: "low-priority"}
	}, 1, "test")
	require.NoError(t, err)

	err = task.RegisterSimpleCataloger("high-priority", func() pkg.Cataloger {
		return &mockCataloger{name: "high-priority"}
	}, 100, "test")
	require.NoError(t, err)

	// Get task factories and verify ordering
	factories := task.DefaultCatalogerRegistry.GetFactories()
	cfg := task.CatalogingFactoryConfig{}
	tasks, err := factories.Tasks(cfg)
	require.NoError(t, err)
	require.Len(t, tasks, 2)

	// Higher priority should come first in the external catalogers
	// (Note: built-in catalogers are added after external ones)
	externalTaskNames := []string{tasks[0].Name(), tasks[1].Name()}
	assert.Equal(t, "high-priority", externalTaskNames[0])
	assert.Equal(t, "low-priority", externalTaskNames[1])
}
