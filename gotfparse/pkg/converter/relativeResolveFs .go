package converter

import (
	"io/fs"
	"os"
	"path/filepath"
)

type relativeResolveFs struct {
	rootDir string
}

func newRelativeResolveFs(rootDir string) fs.FS {
	return &relativeResolveFs{rootDir: rootDir}
}

func (i relativeResolveFs) Open(name string) (fs.File, error) {
	fullPath := filepath.Join(i.rootDir, name)
	return os.Open(fullPath)
}

var _ fs.FS = new(relativeResolveFs)
