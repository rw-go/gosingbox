package singbox

import (
	"testing"
)

func TestWireQueryStatsSkipsUnknownFields(t *testing.T) {
	// field 7, length-delimited payload "ignored", followed by a valid stat.
	data := []byte{0x3a, 0x07, 'i', 'g', 'n', 'o', 'r', 'e', 'd', 0x0a, 0x07, 0x0a, 0x03, 'u', 's', 'r', 0x10, 0x2a}
	var response wireQueryStatsResponse
	if err := response.unmarshal(data); err != nil {
		t.Fatalf("unmarshal returned error: %v", err)
	}
	if len(response.Stat) != 1 || response.Stat[0].Name != "usr" || response.Stat[0].Value != 42 {
		t.Fatalf("stats = %#v", response.Stat)
	}
}

func TestWireQueryStatsRejectsTruncatedVarint(t *testing.T) {
	var response wireQueryStatsResponse
	if err := response.unmarshal([]byte{0x80}); err == nil {
		t.Fatal("truncated varint unexpectedly accepted")
	}
}
