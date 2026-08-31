package app

import "testing"

func TestResolveIpListExpandsExternalName(t *testing.T) {
	a := &App{}
	got := a.resolveIpList([]string{"ext:office", "192.0.2.1"}, map[string][]string{
		"ext:office": {"192.0.2.0/24"},
	})
	want := []string{"192.0.2.0/24", "192.0.2.1"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Fatalf("resolveIpList = %#v, want %#v", got, want)
	}
}
