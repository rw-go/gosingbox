package asn

import (
	"os"
	"path/filepath"
	"testing"
)

func TestLoadAndPrefixesFor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "asn-prefixes.json")
	data := `{"13335":{"ipv4":["1.0.0.0/24","1.1.1.0/24"],"ipv6":["2400:cb00::/32"]},"15169":{"ipv4":["8.8.8.0/24"]}}`
	if err := os.WriteFile(path, []byte(data), 0o644); err != nil {
		t.Fatal(err)
	}

	idx, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if !idx.Available() {
		t.Fatal("expected index to be available")
	}

	p, ok := idx.PrefixesFor(13335)
	if !ok {
		t.Fatal("expected ASN 13335 present")
	}
	if len(p) != 3 {
		t.Fatalf("expected 3 combined prefixes, got %d", len(p))
	}

	if _, ok := idx.PrefixesFor(99999); ok {
		t.Fatal("expected unknown ASN to return false")
	}

	var nilIdx *Index
	if nilIdx.Available() {
		t.Fatal("nil index must not be available")
	}
	if _, ok := nilIdx.PrefixesFor(1); ok {
		t.Fatal("nil index PrefixesFor must return false")
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "nope.json")); err == nil {
		t.Fatal("expected error for missing file")
	}
}
