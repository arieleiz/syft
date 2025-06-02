package file

import (
	"archive/zip"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/anchore/syft/internal"
)

// ZipArchiveReader provides memory-efficient access to ZIP archives using central directory indexing
type ZipArchiveReader struct {
	readerAt  io.ReaderAt
	zipReader *zip.Reader
	closer    io.Closer
	manifest  *archiveManifest
}

// NewZipArchiveReader creates a new ZIP archive reader from a ReaderAt
func NewZipArchiveReader(readerAt io.ReaderAt, size int64, closer io.Closer) (*ZipArchiveReader, error) {
	zipReader, err := zip.NewReader(readerAt, size)
	if err != nil {
		return nil, fmt.Errorf("unable to create zip reader: %w", err)
	}

	// Build manifest from ZIP central directory
	manifest := newArchiveManifest()
	for _, file := range zipReader.File {
		manifest.Add(file.Name, file.FileInfo())
	}

	return &ZipArchiveReader{
		readerAt:  readerAt,
		zipReader: zipReader,
		closer:    closer,
		manifest:  manifest,
	}, nil
}

// NewZipArchiveReaderFromFile creates a ZIP archive reader from a file path
func NewZipArchiveReaderFromFile(archivePath string) (*ZipArchiveReader, error) {
	zipReadCloser, err := OpenZip(archivePath)
	if err != nil {
		return nil, fmt.Errorf("unable to open zip archive: %w", err)
	}

	// Build manifest from ZIP central directory
	manifest := newArchiveManifest()
	for _, file := range zipReadCloser.File {
		manifest.Add(file.Name, file.FileInfo())
	}

	return &ZipArchiveReader{
		readerAt:  nil, // Will use zipReadCloser.Reader directly
		zipReader: zipReadCloser.Reader,
		closer:    zipReadCloser,
		manifest:  manifest,
	}, nil
}

func (z *ZipArchiveReader) GetManifest() ArchiveManifest {
	return z.manifest
}

func (z *ZipArchiveReader) OpenFile(path string) (io.ReadCloser, error) {
	// Find file in ZIP central directory
	for _, file := range z.zipReader.File {
		if file.Name == path {
			return file.Open()
		}
	}
	return nil, os.ErrNotExist
}

func (z *ZipArchiveReader) GetFileContent(path string) (string, error) {
	reader, err := z.OpenFile(path)
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

func (z *ZipArchiveReader) Close() error {
	if z.closer != nil {
		return z.closer.Close()
	}
	return nil
}