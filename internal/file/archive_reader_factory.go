package file

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/anchore/syft/internal"
	"github.com/anchore/syft/syft/file"
)

// CreateArchiveReader creates an appropriate ArchiveReader based on the content type
func CreateArchiveReader(reader file.LocationReadCloser) (ArchiveReader, error) {
	// We need to detect the archive type, but we also need a seekable reader
	// Use buffered seek reader to avoid consuming the original stream
	bufferedReader := internal.NewBufferedSeeker(reader)

	// Detect archive type by reading magic bytes
	magicBytes := make([]byte, 512)
	n, err := bufferedReader.Read(magicBytes)
	if err != nil && err != io.EOF {
		return nil, fmt.Errorf("unable to read magic bytes: %w", err)
	}
	magicBytes = magicBytes[:n]

	// Reset to beginning
	_, err = bufferedReader.Seek(0, io.SeekStart)
	if err != nil {
		return nil, fmt.Errorf("unable to seek to start: %w", err)
	}

	if isZipArchive(magicBytes) {
		return createZipArchiveReader(bufferedReader, reader)
	} else if isTarArchive(magicBytes) {
		return NewTarArchiveReader(bufferedReader, reader)
	}

	return nil, fmt.Errorf("unsupported archive type")
}

// CreateArchiveReaderFromFile creates an ArchiveReader from a file path
func CreateArchiveReaderFromFile(archivePath string) (ArchiveReader, error) {
	file, err := os.Open(archivePath)
	if err != nil {
		return nil, fmt.Errorf("unable to open archive file: %w", err)
	}

	// Detect archive type
	magicBytes := make([]byte, 512)
	n, err := file.Read(magicBytes)
	if err != nil && err != io.EOF {
		file.Close()
		return nil, fmt.Errorf("unable to read magic bytes: %w", err)
	}
	magicBytes = magicBytes[:n]

	// Reset to beginning
	_, err = file.Seek(0, io.SeekStart)
	if err != nil {
		file.Close()
		return nil, fmt.Errorf("unable to seek to start: %w", err)
	}

	if isZipArchive(magicBytes) {
		file.Close() // Close and use specialized ZIP reader
		return NewZipArchiveReaderFromFile(archivePath)
	} else if isTarArchive(magicBytes) {
		return NewTarArchiveReader(file, file)
	}

	file.Close()
	return nil, fmt.Errorf("unsupported archive type")
}

func createZipArchiveReader(bufferedReader io.ReadSeeker, closer io.Closer) (ArchiveReader, error) {
	// For ZIP files, we need ReaderAt interface
	// Convert the seekable reader to ReaderAt
	readerAt := &seekerToReaderAt{reader: bufferedReader}
	
	// Get size by seeking to end
	size, err := bufferedReader.Seek(0, io.SeekEnd)
	if err != nil {
		return nil, fmt.Errorf("unable to get archive size: %w", err)
	}
	
	// Reset to beginning
	_, err = bufferedReader.Seek(0, io.SeekStart)
	if err != nil {
		return nil, fmt.Errorf("unable to seek to start: %w", err)
	}

	return NewZipArchiveReader(readerAt, size, closer)
}

// seekerToReaderAt adapts an io.ReadSeeker to io.ReaderAt
type seekerToReaderAt struct {
	reader io.ReadSeeker
}

func (s *seekerToReaderAt) ReadAt(p []byte, off int64) (n int, err error) {
	// Save current position
	currentPos, err := s.reader.Seek(0, io.SeekCurrent)
	if err != nil {
		return 0, err
	}

	// Seek to desired offset
	_, err = s.reader.Seek(off, io.SeekStart)
	if err != nil {
		return 0, err
	}

	// Read data
	n, err = s.reader.Read(p)

	// Restore original position
	_, seekErr := s.reader.Seek(currentPos, io.SeekStart)
	if seekErr != nil && err == nil {
		err = seekErr
	}

	return n, err
}

// isZipArchive checks if the magic bytes indicate a ZIP archive
func isZipArchive(magicBytes []byte) bool {
	if len(magicBytes) < 4 {
		return false
	}
	// ZIP local file header signature: 0x504b0304 (PK\003\004)
	// ZIP central directory signature: 0x504b0102 (PK\001\002)  
	// ZIP end of central dir signature: 0x504b0506 (PK\005\006)
	return bytes.HasPrefix(magicBytes, []byte{0x50, 0x4b, 0x03, 0x04}) ||
		   bytes.HasPrefix(magicBytes, []byte{0x50, 0x4b, 0x01, 0x02}) ||
		   bytes.HasPrefix(magicBytes, []byte{0x50, 0x4b, 0x05, 0x06})
}

// isTarArchive checks if the magic bytes indicate a TAR archive
func isTarArchive(magicBytes []byte) bool {
	if len(magicBytes) < 512 {
		return false
	}
	// TAR magic is at offset 257: "ustar\x00" or "ustar  \x00"
	if len(magicBytes) >= 262 {
		magic := magicBytes[257:262]
		return bytes.Equal(magic, []byte("ustar"))
	}
	return false
}