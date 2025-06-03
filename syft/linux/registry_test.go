package linux

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/anchore/syft/syft/file"
	"github.com/anchore/syft/syft/source"
	"github.com/anchore/syft/syft/source/directorysource"
)

func TestRegistry_RegisterParser(t *testing.T) {
	tests := []struct {
		name        string
		path        string
		parser      ParseFunc
		priority    int
		expectError bool
	}{
		{
			name:     "valid parser registration",
			path:     "/test/path",
			parser:   func(string) (*Release, error) { return nil, nil },
			priority: 10,
		},
		{
			name:        "nil parser should error",
			path:        "/test/path",
			parser:      nil,
			priority:    10,
			expectError: true,
		},
		{
			name:     "empty path is allowed",
			path:     "",
			parser:   func(string) (*Release, error) { return nil, nil },
			priority: 5,
		},
		{
			name:     "negative priority is allowed",
			path:     "/test/negative",
			parser:   func(string) (*Release, error) { return nil, nil },
			priority: -100,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			registry := NewRegistry()

			err := registry.RegisterParser(tt.path, tt.parser, tt.priority)

			if tt.expectError {
				assert.Error(t, err)
				return
			}

			require.NoError(t, err)

			// Verify parser was registered
			parsers := registry.GetParsers()
			found := false
			for _, entry := range parsers {
				if entry.path == tt.path && entry.priority == tt.priority {
					found = true
					break
				}
			}
			assert.True(t, found, "parser should be registered")
		})
	}
}

func TestRegistry_ParserPriority(t *testing.T) {
	registry := NewRegistry()

	// Register parsers with different priorities
	lowParser := func(string) (*Release, error) {
		return &Release{ID: "low"}, nil
	}
	highParser := func(string) (*Release, error) {
		return &Release{ID: "high"}, nil
	}

	err := registry.RegisterParser("/test/path", lowParser, 1)
	require.NoError(t, err)

	err = registry.RegisterParser("/test/path", highParser, 10)
	require.NoError(t, err)

	parsers := registry.GetParsers()

	// Find the entries for our test path
	var testEntries []parseEntry
	for _, entry := range parsers {
		if entry.path == "/test/path" {
			testEntries = append(testEntries, entry)
		}
	}

	require.Len(t, testEntries, 2)

	// Higher priority should come first
	assert.Equal(t, 10, testEntries[0].priority)
	assert.Equal(t, 1, testEntries[1].priority)
}

func TestRegistry_GetParsers_ThreadSafe(t *testing.T) {
	registry := NewRegistry()

	// Get initial copy
	parsers1 := registry.GetParsers()
	initialCount := len(parsers1)

	// Register a new parser
	err := registry.RegisterParser("/test/concurrent", func(string) (*Release, error) { return nil, nil }, 5)
	require.NoError(t, err)

	// Original copy should be unchanged (defensive copy)
	assert.Len(t, parsers1, initialCount)

	// New copy should have additional parser
	parsers2 := registry.GetParsers()
	assert.Len(t, parsers2, initialCount+1)
}

func TestRegistry_BuiltinParsers(t *testing.T) {
	registry := NewRegistry()
	parsers := registry.GetParsers()

	// Should have built-in parsers
	assert.Greater(t, len(parsers), 0)

	// Check for expected built-in paths
	expectedPaths := []string{
		"/etc/os-release",
		"/usr/lib/os-release",
		"/etc/system-release-cpe",
		"/etc/redhat-release",
		"/bin/busybox",
	}

	foundPaths := make(map[string]bool)
	for _, entry := range parsers {
		foundPaths[entry.path] = true
	}

	for _, path := range expectedPaths {
		assert.True(t, foundPaths[path], "should have built-in parser for %s", path)
	}

	// Busybox should have lowest priority
	busyboxEntry := findEntryByPath(parsers, "/bin/busybox")
	require.NotNil(t, busyboxEntry)
	assert.Equal(t, -1000, busyboxEntry.priority, "busybox should have very low priority")
}

func TestRegistry_ExternalParserIntegration(t *testing.T) {
	// Test that external parsers work with the identification process using real Garden Linux fixture
	registry := NewRegistry()

	// Create a test source using the real Garden Linux fixture
	src, err := directorysource.NewFromPath("test-fixtures")
	require.NoError(t, err)

	resolver, err := src.FileResolver(source.SquashedScope)
	require.NoError(t, err)

	// First, test without custom parser - should use built-in os-release parser
	release := registry.IdentifyRelease(resolver)
	if release != nil {
		// The built-in parser should handle it as a basic os-release
		assert.Equal(t, "gardenlinux", release.ID)
	}

	// Now register a custom Garden Linux parser with enhanced parsing
	gardenParser := func(content string) (*Release, error) {
		if !contains(content, "gardenlinux") {
			return nil, nil // not our distro
		}

		// Parse the actual Garden Linux content with custom logic
		lines := strings.Split(content, "\n")
		values := make(map[string]string)
		for _, line := range lines {
			parts := strings.SplitN(line, "=", 2)
			if len(parts) == 2 {
				key := strings.TrimSpace(parts[0])
				value := strings.Trim(strings.TrimSpace(parts[1]), `"`)
				values[key] = value
			}
		}

		return &Release{
			ID:           "gardenlinux",
			Name:         values["NAME"],
			PrettyName:   values["PRETTY_NAME"],
			ImageVersion: values["IMAGE_VERSION"],
			IDLike:       []string{"debian"}, // Ensure compatibility with debian catalogers
			HomeURL:      values["HOME_URL"],
			SupportURL:   values["SUPPORT_URL"],
			BugReportURL: values["BUG_REPORT_URL"],
			// Add custom Garden Linux fields if needed
			BuildID: values["GARDENLINUX_VERSION"],
		}, nil
	}

	// Register with high priority to override built-in parser
	err = registry.RegisterParser("garden-linux", gardenParser, 200)
	require.NoError(t, err)

	// Test identification with custom parser
	release = registry.IdentifyRelease(resolver)
	require.NotNil(t, release)
	assert.Equal(t, "gardenlinux", release.ID)
	assert.Equal(t, "Garden Linux", release.Name)
	assert.Contains(t, release.IDLike, "debian")
	assert.Contains(t, release.PrettyName, "Garden Linux")
	assert.Equal(t, "1877.0", release.BuildID) // From GARDENLINUX_VERSION
}

func TestDefaultRegistry_RegisterParser(t *testing.T) {
	// Test the package-level convenience function
	originalParsers := DefaultRegistry.GetParsers()
	originalCount := len(originalParsers)

	testParser := func(string) (*Release, error) { return nil, nil }

	err := RegisterParser("/test/default", testParser, 50)
	require.NoError(t, err)

	newParsers := DefaultRegistry.GetParsers()
	assert.Len(t, newParsers, originalCount+1)

	// Find our parser
	found := false
	for _, entry := range newParsers {
		if entry.path == "/test/default" && entry.priority == 50 {
			found = true
			break
		}
	}
	assert.True(t, found)
}

// Helper functions for tests

func findEntryByPath(entries []parseEntry, path string) *parseEntry {
	for _, entry := range entries {
		if entry.path == path {
			return &entry
		}
	}
	return nil
}

func contains(s, substr string) bool {
	return len(substr) > 0 && len(s) >= len(substr) &&
		func() bool {
			for i := 0; i <= len(s)-len(substr); i++ {
				if s[i:i+len(substr)] == substr {
					return true
				}
			}
			return false
		}()
}

// mockResolver for testing
type mockResolver struct {
	files map[string]string
}

func (m *mockResolver) FilesByPath(path string) ([]file.Location, error) {
	if _, exists := m.files[path]; exists {
		return []file.Location{{
			LocationData: file.LocationData{
				Coordinates: file.NewCoordinates(path, ""),
				AccessPath:  path,
			},
		}}, nil
	}
	return nil, fmt.Errorf("file not found: %s", path)
}

func (m *mockResolver) FileContentsByLocation(location file.Location) (file.LocationReadCloser, error) {
	content, exists := m.files[location.RealPath]
	if !exists {
		return file.LocationReadCloser{}, fmt.Errorf("file not found: %s", location.RealPath)
	}

	return file.NewLocationReadCloser(location, &mockReadCloser{content: content}), nil
}

func (m *mockResolver) AllLocations(ctx context.Context) <-chan file.Location {
	ch := make(chan file.Location)
	go func() {
		defer close(ch)
		for path := range m.files {
			ch <- file.Location{
				LocationData: file.LocationData{
					Coordinates: file.NewCoordinates(path, ""),
					AccessPath:  path,
				},
			}
		}
	}()
	return ch
}

func (m *mockResolver) FilesByGlob(...string) ([]file.Location, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockResolver) FilesByMIMEType(...string) ([]file.Location, error) {
	return nil, fmt.Errorf("not implemented")
}

func (m *mockResolver) HasPath(path string) bool {
	_, exists := m.files[path]
	return exists
}

func (m *mockResolver) RelativeFileByPath(file.Location, string) *file.Location {
	return nil
}

func (m *mockResolver) FileMetadataByLocation(location file.Location) (file.Metadata, error) {
	if _, exists := m.files[location.RealPath]; !exists {
		return file.Metadata{}, fmt.Errorf("file not found: %s", location.RealPath)
	}
	return file.Metadata{}, nil
}

type mockReadCloser struct {
	content string
	pos     int
}

func (m *mockReadCloser) Read(p []byte) (int, error) {
	if m.pos >= len(m.content) {
		return 0, fmt.Errorf("EOF")
	}

	remaining := len(m.content) - m.pos
	if len(p) > remaining {
		copy(p, m.content[m.pos:])
		m.pos = len(m.content)
		return remaining, nil
	}

	copy(p, m.content[m.pos:m.pos+len(p)])
	m.pos += len(p)
	return len(p), nil
}

func (m *mockReadCloser) Close() error {
	return nil
}
