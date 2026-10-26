package credentials

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
)

const maxSecretSize = 64 * 1024

// FileSecrets reads secrets from files and caches them keyed by the file's
// identity (os.SameFile, size, mtime). Every lookup does one stat(2); the
// file is re-read only when it changed. There is no background polling: a
// rotated password is picked up by the very next backend connection.
//
// Rotate secrets atomically: write a new file and rename(2) it over the old
// one (Docker/Kubernetes secret mounts already do this). An in-place
// truncate-and-write could briefly expose a partial value.
type FileSecrets struct {
	mu    sync.Mutex
	cache map[string]fileEntry
}

type fileEntry struct {
	info  os.FileInfo
	value string
}

func NewFileSecrets() *FileSecrets { return &FileSecrets{cache: map[string]fileEntry{}} }

func (f *FileSecrets) Get(path string) (string, error) {
	fi, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	f.mu.Lock()
	e, ok := f.cache[path]
	f.mu.Unlock()
	if ok && os.SameFile(e.info, fi) && e.info.Size() == fi.Size() && e.info.ModTime().Equal(fi.ModTime()) {
		return e.value, nil
	}

	v, err := readSecretFile(path)
	if err != nil {
		return "", err
	}
	f.mu.Lock()
	f.cache[path] = fileEntry{info: fi, value: v}
	f.mu.Unlock()
	return v, nil
}

func readSecretFile(path string) (string, error) {
	fh, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer fh.Close()
	b, err := io.ReadAll(io.LimitReader(fh, maxSecretSize+1))
	if err != nil {
		return "", fmt.Errorf("secret file: %w", err)
	}
	if len(b) > maxSecretSize {
		return "", errors.New("secret file too large")
	}
	// A single trailing newline (as left by most editors and `echo`) is not
	// part of the secret.
	v := strings.TrimSuffix(strings.TrimSuffix(string(b), "\n"), "\r")
	if v == "" {
		return "", errors.New("secret file is empty")
	}
	return v, nil
}
