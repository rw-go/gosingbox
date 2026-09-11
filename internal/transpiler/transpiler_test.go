package transpiler

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestBuildRoutingPreservesExactAndCIDRMatchers(t *testing.T) {
	cfg := map[string]any{
		"routing": map[string]any{"rules": []any{map[string]any{
			"domain":      []any{"full:example.com"},
			"ip":          []any{"192.0.2.0/24"},
			"outboundTag": "block",
		}}},
	}
	route, _ := buildRouting(cfg, map[string]bool{"block": true})
	if route == nil {
		t.Fatal("route is nil")
	}
	rules := route["rules"].([]any)
	// Because rules contain domain matching, top rule is auto-injected `action: sniff`.
	if len(rules) != 2 {
		t.Fatalf("rules = %#v", rules)
	}
	if sniffAction, ok := rules[0].(map[string]any); !ok || sniffAction["action"] != "sniff" {
		t.Fatalf("expected action: sniff, got %#v", rules[0])
	}
	rule := rules[1].(map[string]any)
	if got := rule["domain"].([]string); len(got) != 1 || got[0] != "example.com" {
		t.Fatalf("domain = %#v", rule["domain"])
	}
	if got := rule["ip_cidr"].([]string); len(got) != 1 || got[0] != "192.0.2.0/24" {
		t.Fatalf("ip_cidr = %#v", rule["ip_cidr"])
	}
}

func TestTranspileAcceptsCIDRRoute(t *testing.T) {
	raw, err := json.Marshal(map[string]any{
		"inbounds": []any{map[string]any{
			"protocol": "vless", "port": 443, "tag": "vless-in",
			"streamSettings": map[string]any{"security": "reality", "realitySettings": map[string]any{
				"privateKey": "key", "serverNames": []any{"example.com"},
			}},
		}},
		"outbounds": []any{map[string]any{"protocol": "freedom", "tag": "direct"}},
		"routing": map[string]any{"rules": []any{map[string]any{
			"ip": []any{"192.0.2.0/24"}, "outboundTag": "direct",
		}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	result, err := Transpile(raw, "127.0.0.1:6450", "127.0.0.1:9090", "warn", nil, nil)
	if err != nil {
		t.Fatalf("Transpile returned error: %v", err)
	}
	if result.Config["route"] == nil {
		t.Fatal("route was dropped")
	}
}

func TestBuildRoutingDropsUnknownOutbound(t *testing.T) {
	cfg := map[string]any{
		"routing": map[string]any{"rules": []any{
			map[string]any{"domain": []any{"full:example.com"}, "outboundTag": "REMNAWAVE_API"},
			map[string]any{"domain": []any{"full:example.com"}, "outboundTag": "block"},
		}},
	}
	route, _ := buildRouting(cfg, map[string]bool{"block": true})
	if route == nil {
		t.Fatal("route is nil")
	}
	rules := route["rules"].([]any)
	// rules contains auto-injected action: sniff + the 1 valid rule
	if len(rules) != 2 {
		t.Fatalf("expected 2 rules (sniff + valid outbound rule), got %d", len(rules))
	}
	rule := rules[1].(map[string]any)
	if got := rule["outbound"]; got != "block" {
		t.Fatalf("outbound = %#v, want block", got)
	}
}

func TestBuildRoutingSniffingInjection(t *testing.T) {
	// Case 1: purely IP-based rule without sniffing inbound -> no sniff rule injected
	cfgIP := map[string]any{
		"routing": map[string]any{"rules": []any{
			map[string]any{"ip": []any{"1.1.1.1"}, "outboundTag": "direct"},
		}},
	}
	routeIP, _ := buildRouting(cfgIP, map[string]bool{"direct": true})
	rulesIP := routeIP["rules"].([]any)
	if len(rulesIP) != 1 {
		t.Fatalf("expected 1 rule without sniffing, got %d", len(rulesIP))
	}

	// Case 2: purely IP-based rule WITH inbound sniffing enabled -> sniff rule injected
	cfgInboundSniff := map[string]any{
		"inbounds": []any{
			map[string]any{
				"protocol": "vless",
				"sniffing": map[string]any{"enabled": true},
			},
		},
		"routing": map[string]any{"rules": []any{
			map[string]any{"ip": []any{"1.1.1.1"}, "outboundTag": "direct"},
		}},
	}
	routeSniff, _ := buildRouting(cfgInboundSniff, map[string]bool{"direct": true})
	rulesSniff := routeSniff["rules"].([]any)
	if len(rulesSniff) != 2 {
		t.Fatalf("expected 2 rules with inbound sniffing, got %d", len(rulesSniff))
	}
	if action, ok := rulesSniff[0].(map[string]any); !ok || action["action"] != "sniff" {
		t.Fatalf("expected action: sniff, got %#v", rulesSniff[0])
	}
}

func TestParseDestSupportsIPv6(t *testing.T) {
	for _, tc := range []struct {
		input string
		host  string
		port  int
	}{
		{input: "[2001:db8::1]:8443", host: "2001:db8::1", port: 8443},
		{input: "2001:db8::1", host: "2001:db8::1", port: 443},
		{input: "example.com:8443", host: "example.com", port: 8443},
	} {
		host, port := parseDest(tc.input, "fallback.example")
		if host != tc.host || port != tc.port {
			t.Errorf("parseDest(%q) = %q:%d, want %q:%d", tc.input, host, port, tc.host, tc.port)
		}
	}
}

func TestSplitPortsSupportsXrayForms(t *testing.T) {
	ports, ranges := splitPorts("80,443,1000-2000")
	if len(ports) != 2 || ports[0] != 80 || ports[1] != 443 {
		t.Fatalf("ports = %#v", ports)
	}
	if len(ranges) != 1 || ranges[0] != "1000-2000" {
		t.Fatalf("ranges = %#v", ranges)
	}
	ports, ranges = splitPorts(float64(8443))
	if len(ports) != 1 || ports[0] != 8443 || len(ranges) != 0 {
		t.Fatalf("numeric port = %#v, %#v", ports, ranges)
	}
}

func TestBuildRoutingFiltersInvalidGeoRuleSetNames(t *testing.T) {
	cfg := map[string]any{
		"routing": map[string]any{"rules": []any{
			map[string]any{
				"domain":      []any{"geosite:cn", "geosite:../../evil", "geosite:valid-name_1"},
				"ip":          []any{"geoip:private", "geoip:../bad/path", "geoip:cn"},
				"outboundTag": "direct",
			},
		}},
	}
	route, _ := buildRouting(cfg, map[string]bool{"direct": true})
	if route == nil {
		t.Fatal("route is nil")
	}
	ruleSets, ok := route["rule_set"].([]any)
	if !ok || len(ruleSets) == 0 {
		t.Fatalf("expected rule sets, got %#v", route["rule_set"])
	}
	for _, rsAny := range ruleSets {
		rs := rsAny.(map[string]any)
		tag := rs["tag"].(string)
		if strings.Contains(tag, "..") || strings.Contains(tag, "/") {
			t.Fatalf("invalid rule set tag leaked: %s", tag)
		}
	}
}
