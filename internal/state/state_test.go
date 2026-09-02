package state

import (
	"testing"

	"github.com/rwnode/rwnode-gosingbox/internal/transpiler"
)

func TestCommitConfigCopiesAllInputs(t *testing.T) {
	s := New()
	raw := []byte(`{"inbounds":[]}`)
	vless := []transpiler.VlessUser{{Name: "vless@example.com", UUID: "uuid-1", Flow: "xtls-rprx-vision"}}
	ss := []transpiler.SsUser{{Name: "ss@example.com", Password: "secret"}}
	tags := []string{"in-1"}

	s.CommitConfig(raw, vless, ss, tags)

	raw[0] = 'x'
	vless[0].Name = "changed"
	ss[0].Name = "changed"
	tags[0] = "changed"

	if got := string(s.RawConfig()); got != `{"inbounds":[]}` {
		t.Fatalf("raw config = %q", got)
	}
	if got := s.VlessUsers(); len(got) != 1 || got[0].Name != "vless@example.com" {
		t.Fatalf("vless users = %#v", got)
	}
	if got := s.SsUsers(); len(got) != 1 || got[0].Name != "ss@example.com" {
		t.Fatalf("ss users = %#v", got)
	}
	if got := s.InboundTags(); len(got) != 1 || got[0] != "in-1" {
		t.Fatalf("inbound tags = %#v", got)
	}
}
