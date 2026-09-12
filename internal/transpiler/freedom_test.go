package transpiler

import "testing"

func TestFreedomDomainStrategyMapping(t *testing.T) {
	for _, tc := range []struct {
		input    string
		expected string
	}{
		{"UseIPv4", "ipv4_only"},
		{"ForceIPv4", "ipv4_only"},
		{"useipv4", "ipv4_only"},
		{"UseIPv6", "ipv6_only"},
		{"ForceIPv6", "ipv6_only"},
		{"useipv6", "ipv6_only"},
		{"PreferIPv4", "prefer_ipv4"},
		{"UseIPv4v6", "prefer_ipv4"},
		{"ForceIPv4v6", "prefer_ipv4"},
		{"useipv4v6", "prefer_ipv4"},
		{"PreferIPv6", "prefer_ipv6"},
		{"UseIPv6v4", "prefer_ipv6"},
		{"ForceIPv6v4", "prefer_ipv6"},
		{"useipv6v4", "prefer_ipv6"},
	} {
		cfg := map[string]any{
			"outbounds": []any{
				map[string]any{
					"tag":      "test-out",
					"protocol": "freedom",
					"settings": map[string]any{
						"domainStrategy": tc.input,
					},
				},
			},
		}
		outbounds := buildOutbounds(cfg)
		if len(outbounds) == 0 {
			t.Fatalf("no outbounds built for %s", tc.input)
		}
		ds, ok := outbounds[0]["domain_strategy"].(string)
		if !ok || ds != tc.expected {
			t.Errorf("domainStrategy %q = %q, want %q", tc.input, ds, tc.expected)
		}
	}
}
