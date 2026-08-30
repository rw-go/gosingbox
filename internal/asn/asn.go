// Package asn resolves ASN numbers to IP prefixes for the plugin sharedLists
// "asList" type. It mirrors the Node.js AsnLmdbService but reads the official
// remnawave/asn-index JSON release asset instead of the LMDB variant, keeping
// the Go node dependency-free (standard library only).
//
// The index is optional: when no data file is configured the resolver is
// "unavailable" and asList entries are skipped (the same "ASN not found"
// behaviour as the Node side). Loading the full JSON index is memory-expensive,
// so it stays disabled by default and should only be enabled when the panel
// actually uses asList shared lists.
package asn

import (
	"encoding/json"
	"os"
	"strconv"
	"sync"
)

// Prefixes is one ASN entry from asn-prefixes.json.
type Prefixes struct {
	IPv4 []string `json:"ipv4"`
	IPv6 []string `json:"ipv6"`
}

// Index holds the ASN → prefixes mapping loaded from the official JSON asset.
type Index struct {
	mu sync.RWMutex
	m  map[string]Prefixes
}

// Load reads and parses an asn-prefixes.json file (the shape produced by
// remnawave/asn-index: a single object keyed by ASN number as a string).
func Load(path string) (*Index, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var m map[string]Prefixes
	if err := json.Unmarshal(raw, &m); err != nil {
		return nil, err
	}
	return &Index{m: m}, nil
}

// Available reports whether the index has any entries loaded.
func (i *Index) Available() bool {
	if i == nil {
		return false
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	return len(i.m) > 0
}

// PrefixesFor returns the combined ipv4+ipv6 prefixes for the ASN, or
// (nil, false) when the ASN is unknown.
func (i *Index) PrefixesFor(asn int) ([]string, bool) {
	if i == nil {
		return nil, false
	}
	i.mu.RLock()
	defer i.mu.RUnlock()
	p, ok := i.m[strconv.Itoa(asn)]
	if !ok {
		return nil, false
	}
	out := make([]string, 0, len(p.IPv4)+len(p.IPv6))
	out = append(out, p.IPv4...)
	out = append(out, p.IPv6...)
	return out, true
}
