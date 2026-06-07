package loader

import (
	"fmt"
	"os"
)

type File struct {
	Path    string
	Content []byte
}

// Load reads the file at path from disk
func Load(path string) (File, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return File{}, fmt.Errorf("reading %s: %w", path, err)
	}
	return File{Path: path, Content: content}, nil
}
