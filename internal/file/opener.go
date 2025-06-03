package file

import (
	"io"
	"os"
)

// OpenerInterface defines the contract for opening resources
type OpenerInterface interface {
	Open() (io.ReadCloser, error)
}

// Opener is an object that stores a path to later be opened as a file.
type Opener struct {
	Path string
}

// Open the stored path as a io.ReadCloser.
func (o Opener) Open() (io.ReadCloser, error) {
	return os.Open(o.Path)
}
