package java

import (
	"fmt"

	intFile "github.com/anchore/syft/internal/file"
	"github.com/anchore/syft/syft/file"
)

// memoryArchiveAccessor provides memory-based access to archive contents without disk writes
type memoryArchiveAccessor struct {
	reader   intFile.ArchiveReader
	location file.Location
}

// createMemoryArchiveAccessor replaces saveArchiveToTmp for memory-based archive access
func createMemoryArchiveAccessor(reader file.LocationReadCloser) (*memoryArchiveAccessor, func(), error) {
	archiveReader, err := intFile.CreateArchiveReader(reader)
	if err != nil {
		return nil, func() {}, fmt.Errorf("unable to create archive reader: %w", err)
	}

	accessor := &memoryArchiveAccessor{
		reader:   archiveReader,
		location: reader.Location,
	}

	cleanupFn := func() {
		if err := archiveReader.Close(); err != nil {
			// Log error but don't fail cleanup
		}
	}

	return accessor, cleanupFn, nil
}

// getManifest returns the archive manifest for glob matching (replaces intFile.NewZipFileManifest)
func (m *memoryArchiveAccessor) getManifest() intFile.ArchiveManifest {
	return m.reader.GetManifest()
}

// getFileContents returns contents for multiple files (replaces intFile.ContentsFromZip)
func (m *memoryArchiveAccessor) getFileContents(paths ...string) (map[string]string, error) {
	results := make(map[string]string)

	for _, path := range paths {
		content, err := m.reader.GetFileContent(path)
		if err != nil {
			return nil, fmt.Errorf("unable to read file %s: %w", path, err)
		}
		results[path] = content
	}

	return results, nil
}

// extractNestedArchives returns openers for nested archives (replaces intFile.ExtractFromZipToUniqueTempFile)
func (m *memoryArchiveAccessor) extractNestedArchives(paths ...string) (map[string]intFile.OpenerInterface, error) {
	results := make(map[string]intFile.OpenerInterface)

	for _, path := range paths {
		reader, err := m.reader.OpenFile(path)
		if err != nil {
			return nil, fmt.Errorf("unable to open nested archive %s: %w", path, err)
		}

		// Create a memory-based opener that doesn't write to disk
		results[path] = intFile.MemoryOpener{
			ReadCloser: reader,
		}
	}

	return results, nil
}
