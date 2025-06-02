package file

import (
	"io"
)

// MemoryOpener implements Opener interface for in-memory content access
type MemoryOpener struct {
	ReadCloser io.ReadCloser
}

// Open returns the stored ReadCloser
func (m MemoryOpener) Open() (io.ReadCloser, error) {
	return m.ReadCloser, nil
}