package file

import (
	"io"
	"os"
)

// ArchiveReader provides memory-efficient access to archive contents without extracting to disk
type ArchiveReader interface {
	// GetManifest returns a file listing for glob matching
	GetManifest() ArchiveManifest

	// OpenFile returns a ReadCloser for a specific file path within the archive
	OpenFile(path string) (io.ReadCloser, error)

	// GetFileContent returns string content for a file path within the archive
	GetFileContent(path string) (string, error)

	// Close releases resources associated with the archive reader
	Close() error
}

// ArchiveManifest provides file listing and pattern matching capabilities
type ArchiveManifest interface {
	// GlobMatch returns file paths that match the given patterns
	GlobMatch(caseInsensitive bool, patterns ...string) []string

	// GetFileInfo returns file metadata for a specific path
	GetFileInfo(path string) (os.FileInfo, bool)

	// AllFiles returns all file paths in the archive
	AllFiles() []string
}
