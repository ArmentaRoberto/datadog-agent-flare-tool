package extractor

import (
	"archive/zip"
	"os"
	"path/filepath"
	"sort"
	"testing"
)

// createTestArchive creates a minimal flare zip in a temp dir and returns its path.
func createTestArchive(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "test-flare.zip")

	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	w := zip.NewWriter(f)
	for name, content := range files {
		fw, err := w.Create(name)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write([]byte(content)); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	return path
}

func TestOpenAndHostname(t *testing.T) {
	path := createTestArchive(t, map[string]string{
		"myhost/status.log":  "Agent (v7.52.0)",
		"myhost/health.yaml": "collector: healthy",
	})

	archive, err := Open(path)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}
	defer archive.Close()

	if archive.Hostname() != "myhost" {
		t.Errorf("expected hostname 'myhost', got %q", archive.Hostname())
	}
}

func TestReadFile(t *testing.T) {
	path := createTestArchive(t, map[string]string{
		"myhost/status.log": "Agent (v7.52.0)",
	})

	archive, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()

	// Read by relative path
	data, err := archive.ReadFile("status.log")
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	if string(data) != "Agent (v7.52.0)" {
		t.Errorf("unexpected content: %q", string(data))
	}
}

func TestHasFile(t *testing.T) {
	path := createTestArchive(t, map[string]string{
		"myhost/status.log":        "content",
		"myhost/etc/datadog.yaml":  "api_key: test",
	})

	archive, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()

	if !archive.HasFile("status.log") {
		t.Error("expected status.log to exist")
	}
	if !archive.HasFile("etc/datadog.yaml") {
		t.Error("expected etc/datadog.yaml to exist")
	}
	if archive.HasFile("nonexistent.log") {
		t.Error("expected nonexistent.log to not exist")
	}
}

func TestListDir(t *testing.T) {
	path := createTestArchive(t, map[string]string{
		"myhost/etc/datadog.yaml":   "content",
		"myhost/etc/confd/cpu.yaml": "content",
		"myhost/etc/confd/disk.yaml": "content",
		"myhost/status.log":         "content",
	})

	archive, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()

	files := archive.ListDir("etc/confd/")
	sort.Strings(files)

	if len(files) != 2 {
		t.Fatalf("expected 2 files in etc/confd/, got %d: %v", len(files), files)
	}
}

func TestFileSize(t *testing.T) {
	content := "hello world"
	path := createTestArchive(t, map[string]string{
		"myhost/test.log": content,
	})

	archive, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()

	size := archive.FileSize("test.log")
	if size != int64(len(content)) {
		t.Errorf("expected size %d, got %d", len(content), size)
	}
}

func TestReadFileMissing(t *testing.T) {
	path := createTestArchive(t, map[string]string{
		"myhost/status.log": "content",
	})

	archive, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()

	_, err = archive.ReadFile("nonexistent.log")
	if err == nil {
		t.Error("expected error reading nonexistent file")
	}
}

func TestTotalFiles(t *testing.T) {
	path := createTestArchive(t, map[string]string{
		"myhost/a.log": "a",
		"myhost/b.log": "b",
		"myhost/c.log": "c",
	})

	archive, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer archive.Close()

	if archive.TotalFiles() != 3 {
		t.Errorf("expected 3 files, got %d", archive.TotalFiles())
	}
}
