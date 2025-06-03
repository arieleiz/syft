package file

import (
	"os"
	"sort"
	"strings"

	"github.com/scylladb/go-set/strset"
)

// archiveManifest implements ArchiveManifest interface
type archiveManifest struct {
	files map[string]os.FileInfo
}

func newArchiveManifest() *archiveManifest {
	return &archiveManifest{
		files: make(map[string]os.FileInfo),
	}
}

func (m *archiveManifest) Add(path string, info os.FileInfo) {
	m.files[path] = info
}

func (m *archiveManifest) GlobMatch(caseInsensitive bool, patterns ...string) []string {
	uniqueMatches := strset.New()

	for _, pattern := range patterns {
		for entry := range m.files {
			// Normalize entry name to match ZIP behavior (leading slash)
			normalizedEntry := normalizeArchiveEntryName(caseInsensitive, entry)

			if caseInsensitive {
				pattern = strings.ToLower(pattern)
			}
			if GlobMatch(pattern, normalizedEntry) {
				uniqueMatches.Add(entry)
			}
		}
	}

	results := uniqueMatches.List()
	sort.Strings(results)
	return results
}

func (m *archiveManifest) GetFileInfo(path string) (os.FileInfo, bool) {
	info, exists := m.files[path]
	return info, exists
}

func (m *archiveManifest) AllFiles() []string {
	paths := make([]string, 0, len(m.files))
	for path := range m.files {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

// normalizeArchiveEntryName ensures the entry is prefixed with "/" for consistent glob matching
func normalizeArchiveEntryName(caseInsensitive bool, entry string) string {
	if caseInsensitive {
		entry = strings.ToLower(entry)
	}
	if !strings.HasPrefix(entry, "/") {
		return "/" + entry
	}
	return entry
}
