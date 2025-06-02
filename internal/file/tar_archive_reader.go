package file

import (
	"archive/tar"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/anchore/syft/internal"
)

// TarArchiveReader provides memory-efficient access to TAR archives using offset indexing
type TarArchiveReader struct {
	reader   io.ReadSeeker
	closer   io.Closer
	index    map[string]*TarFileEntry
	manifest *archiveManifest
}

// TarFileEntry represents metadata and location of a file within a TAR archive
type TarFileEntry struct {
	Offset int64
	Size   int64
	Header *tar.Header
}

// NewTarArchiveReader creates a TAR archive reader with offset indexing
func NewTarArchiveReader(reader io.ReadSeeker, closer io.Closer) (*TarArchiveReader, error) {
	// Build offset index by scanning TAR headers
	index, manifest, err := buildTarIndex(reader)
	if err != nil {
		return nil, fmt.Errorf("unable to build tar index: %w", err)
	}

	return &TarArchiveReader{
		reader:   reader,
		closer:   closer,
		index:    index,
		manifest: manifest,
	}, nil
}

// buildTarIndex scans through the TAR archive once to build an offset index
func buildTarIndex(reader io.ReadSeeker) (map[string]*TarFileEntry, *archiveManifest, error) {
	// Ensure we start at the beginning
	_, err := reader.Seek(0, io.SeekStart)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to seek to start: %w", err)
	}

	index := make(map[string]*TarFileEntry)
	manifest := newArchiveManifest()
	tarReader := tar.NewReader(reader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, nil, fmt.Errorf("unable to read tar header: %w", err)
		}

		// Get current position after header (this is where file data starts)
		dataOffset, err := reader.Seek(0, io.SeekCurrent)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to get data offset: %w", err)
		}

		// Store file entry with data offset and size
		index[header.Name] = &TarFileEntry{
			Offset: dataOffset,
			Size:   header.Size,
			Header: header,
		}

		// Add to manifest
		manifest.Add(header.Name, header.FileInfo())
	}

	return index, manifest, nil
}

func (t *TarArchiveReader) GetManifest() ArchiveManifest {
	return t.manifest
}

func (t *TarArchiveReader) OpenFile(path string) (io.ReadCloser, error) {
	entry, exists := t.index[path]
	if !exists {
		return nil, os.ErrNotExist
	}

	// Skip directories
	if entry.Header.FileInfo().IsDir() {
		return nil, fmt.Errorf("cannot open directory as file: %s", path)
	}

	// Seek to file data
	_, err := t.reader.Seek(entry.Offset, io.SeekStart)
	if err != nil {
		return nil, fmt.Errorf("unable to seek to file data: %w", err)
	}

	// Return limited reader for just this file's content
	limitedReader := io.LimitReader(t.reader, entry.Size)
	return io.NopCloser(limitedReader), nil
}

func (t *TarArchiveReader) GetFileContent(path string) (string, error) {
	reader, err := t.OpenFile(path)
	if err != nil {
		return "", err
	}
	defer internal.CloseAndLogError(reader, path)

	var builder strings.Builder
	_, err = io.Copy(&builder, reader)
	if err != nil {
		return "", fmt.Errorf("unable to read file content: %w", err)
	}

	return builder.String(), nil
}

func (t *TarArchiveReader) Close() error {
	if t.closer != nil {
		return t.closer.Close()
	}
	return nil
}