// Package extractor handles opening and reading files from flare zip archives.
package extractor

import (
	"archive/zip"
	"fmt"
	"io"
	"path/filepath"
	"strings"
)

// FlareArchive provides access to files inside a flare zip.
type FlareArchive struct {
	reader   *zip.ReadCloser
	hostname string
	files    map[string]*zip.File
}

// Open opens a flare zip archive and indexes its contents.
func Open(path string) (*FlareArchive, error) {
	r, err := zip.OpenReader(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open flare archive %q: %w", path, err)
	}

	fa := &FlareArchive{
		reader: r,
		files:  make(map[string]*zip.File),
	}

	// Index files and detect hostname (top-level directory)
	for _, f := range r.File {
		parts := strings.SplitN(f.Name, "/", 2)
		if len(parts) >= 1 && fa.hostname == "" && parts[0] != "" {
			fa.hostname = parts[0]
		}
		// Store both the full path and the relative path (after hostname)
		fa.files[f.Name] = f
		if len(parts) == 2 {
			fa.files[parts[1]] = f
		}
	}

	return fa, nil
}

// Close releases the archive resources.
func (fa *FlareArchive) Close() error {
	return fa.reader.Close()
}

// Hostname returns the detected hostname from the archive structure.
func (fa *FlareArchive) Hostname() string {
	return fa.hostname
}

// ReadFile reads the entire content of a file from the archive by its relative path.
func (fa *FlareArchive) ReadFile(name string) ([]byte, error) {
	f, ok := fa.files[name]
	if !ok {
		// Try with hostname prefix
		f, ok = fa.files[fa.hostname+"/"+name]
		if !ok {
			return nil, fmt.Errorf("file %q not found in archive", name)
		}
	}

	rc, err := f.Open()
	if err != nil {
		return nil, fmt.Errorf("failed to open %q: %w", name, err)
	}
	defer rc.Close()

	data, err := io.ReadAll(rc)
	if err != nil {
		return nil, fmt.Errorf("failed to read %q: %w", name, err)
	}
	return data, nil
}

// HasFile checks if a file exists in the archive.
func (fa *FlareArchive) HasFile(name string) bool {
	if _, ok := fa.files[name]; ok {
		return true
	}
	_, ok := fa.files[fa.hostname+"/"+name]
	return ok
}

// ListFiles returns all file paths in the archive (relative to hostname).
func (fa *FlareArchive) ListFiles() []string {
	seen := make(map[string]bool)
	var paths []string
	for _, f := range fa.reader.File {
		rel := f.Name
		parts := strings.SplitN(f.Name, "/", 2)
		if len(parts) == 2 {
			rel = parts[1]
		}
		if rel == "" || seen[rel] {
			continue
		}
		seen[rel] = true
		paths = append(paths, rel)
	}
	return paths
}

// ListDir returns files under a given directory prefix.
func (fa *FlareArchive) ListDir(dir string) []string {
	dir = strings.TrimSuffix(dir, "/") + "/"
	var result []string
	seen := make(map[string]bool)

	for _, f := range fa.reader.File {
		rel := f.Name
		parts := strings.SplitN(f.Name, "/", 2)
		if len(parts) == 2 {
			rel = parts[1]
		}
		if strings.HasPrefix(rel, dir) && rel != dir && !seen[rel] {
			seen[rel] = true
			result = append(result, rel)
		}
	}
	return result
}

// GlobFiles returns files matching a glob pattern (relative to hostname).
func (fa *FlareArchive) GlobFiles(pattern string) []string {
	var result []string
	seen := make(map[string]bool)

	for _, f := range fa.reader.File {
		rel := f.Name
		parts := strings.SplitN(f.Name, "/", 2)
		if len(parts) == 2 {
			rel = parts[1]
		}
		if rel == "" || seen[rel] {
			continue
		}
		seen[rel] = true
		if matched, _ := filepath.Match(pattern, rel); matched {
			result = append(result, rel)
		}
		// Also try matching against just the filename
		if matched, _ := filepath.Match(pattern, filepath.Base(rel)); matched && !seen[rel] {
			result = append(result, rel)
		}
	}
	return result
}

// FileSize returns the uncompressed size of a file.
func (fa *FlareArchive) FileSize(name string) int64 {
	f, ok := fa.files[name]
	if !ok {
		f, ok = fa.files[fa.hostname+"/"+name]
		if !ok {
			return 0
		}
	}
	return int64(f.UncompressedSize64)
}

// TotalFiles returns the total number of files in the archive.
func (fa *FlareArchive) TotalFiles() int {
	return len(fa.reader.File)
}

// TotalSize returns the total uncompressed size of all files.
func (fa *FlareArchive) TotalSize() int64 {
	var total int64
	for _, f := range fa.reader.File {
		total += int64(f.UncompressedSize64)
	}
	return total
}
