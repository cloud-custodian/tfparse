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

// Open allows relative paths leading outside the FS root.
func (i relativeResolveFs) Open(name string) (fs.File, error) {
	fullPath := filepath.Join(i.rootDir, name)
	return os.Open(filepath.FromSlash(fullPath))
}

// Path subverts the FS concept by allowing clients to get the real path.
func (i relativeResolveFs) Path() string {
	return i.rootDir
}

var _ fs.FS = new(relativeResolveFs)
