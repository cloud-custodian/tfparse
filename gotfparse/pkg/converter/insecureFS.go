package converter

import (
	"io/fs"
	"os"
	"path/filepath"
)

type insecureFS struct {
	rootDir string
}

func newInsecureFS(rootDir string) fs.FS {
	return &insecureFS{rootDir: rootDir}
}

func (i insecureFS) Open(name string) (fs.File, error) {
	fullPath := filepath.Join(i.rootDir, name)
	return os.Open(fullPath)
}

var _ fs.FS = new(insecureFS)
