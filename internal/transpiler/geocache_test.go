package transpiler

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestResolveGeoCachePathCreatesDir(t *testing.T) {
	tmpDir := filepath.Join(os.TempDir(), "test-geo-cache")
	defer os.RemoveAll(tmpDir)

	orig := os.Getenv("SINGBOX_GEO_DIR")
	defer os.Setenv("SINGBOX_GEO_DIR", orig)

	os.Setenv("SINGBOX_GEO_DIR", tmpDir)
	got := resolveGeoCachePath()
	if !strings.HasSuffix(got, ".cache.db") {
		t.Fatalf("unexpected cache path: %s", got)
	}
	if fi, err := os.Stat(tmpDir); err != nil || !fi.IsDir() {
		t.Fatalf("expected directory %s to be created, err: %v", tmpDir, err)
	}
}
