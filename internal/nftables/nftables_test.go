package nftables

import "testing"

func TestSetForAcceptsIPAndCIDR(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  string
	}{
		{input: "192.0.2.1", want: "v4"},
		{input: "192.0.2.0/24", want: "v4"},
		{input: "2001:db8::1", want: "v6"},
		{input: "2001:db8::/32", want: "v6"},
	} {
		got := setFor(tc.input, "v4", "v6")
		if got != tc.want {
			t.Errorf("setFor(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestSetForRejectsInvalidAddress(t *testing.T) {
	if got := setFor("not-an-address", "v4", "v6"); got != "" {
		t.Fatalf("setFor invalid address = %q, want empty", got)
	}
}

func TestBatchElements(t *testing.T) {
	got := batchElements([]string{"192.0.2.1", "2001:db8::1"})
	if want := "{ 192.0.2.1, 2001:db8::1 }"; got != want {
		t.Fatalf("batchElements = %q, want %q", got, want)
	}
}
