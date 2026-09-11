// Package transpiler translates a Remnawave panel Xray JSON config into a
// sing-box JSON config. It mirrors the mapping implemented in the Node.js
// version (src/modules/xray-core/singbox-transpiler.ts) exactly.
package transpiler

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"sort"
	"strconv"
	"strings"
)

// VlessUser is a sing-box VLESS user entry.
type VlessUser struct {
	Name string `json:"name"`
	UUID string `json:"uuid"`
	Flow string `json:"flow,omitempty"`
}

// SsUser is a sing-box Shadowsocks 2022 user entry.
type SsUser struct {
	Name     string `json:"name"`
	Password string `json:"password"`
}

// Result is the transpile outcome.
type Result struct {
	Config     map[string]any
	InboundTag string
	Users      []VlessUser
	SsUsers    []SsUser
	ListenPort int
}

// Error indicates an unsupported config.
type Error struct {
	Msg string
}

func (e *Error) Error() string { return e.Msg }

func errf(format string, a ...any) *Error {
	return &Error{Msg: fmt.Sprintf(format, a...)}
}

// Transpile converts the panel xrayConfig JSON into a sing-box config.
// statsListen (v2ray_api) and clashListen (clash_api) are wiring options;
// logLevel is the sing-box log verbosity; desiredUsers, when non-nil,
// overrides the VLESS user list (used by the user-change pipeline); the same
// holds for desiredSsUsers and the Shadowsocks 2022 user list.
func Transpile(raw []byte, statsListen, clashListen, logLevel string, desiredUsers []VlessUser, desiredSsUsers []SsUser) (*Result, error) {
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, errf("panel config is not valid JSON: %v", err)
	}

	xrayInbounds := asArr(cfg["inbounds"])

	// --- Users ---
	vlessUsers := buildVlessUsers(cfg, desiredUsers)
	ssUsers := buildSsUsers(cfg, desiredSsUsers)
	ssUseDesired := desiredSsUsers != nil

	// --- Inbounds ---
	var singBoxInbounds []any
	var inboundTags []string
	var primaryTag string
	var primaryPort = 443

	for _, ibAny := range xrayInbounds {
		ib, ok := ibAny.(map[string]any)
		if !ok {
			continue
		}
		stream, _ := ib["streamSettings"].(map[string]any)
		proto, _ := ib["protocol"].(string)
		switch {
		case proto == "vless" && stream != nil && stream["security"] == "reality":
			mapped := mapVlessInbound(ib, vlessUsers)
			if mapped != nil {
				singBoxInbounds = append(singBoxInbounds, mapped)
				if tag, ok := mapped["tag"].(string); ok {
					inboundTags = append(inboundTags, tag)
				}
				if primaryTag == "" {
					primaryTag, _ = mapped["tag"].(string)
					if p, ok := mapped["listen_port"].(float64); ok {
						primaryPort = int(p)
					}
				}
			}
		case proto == "shadowsocks":
			mapped := mapShadowsocksInbound(ib, ssUsers, ssUseDesired)
			if mapped != nil {
				singBoxInbounds = append(singBoxInbounds, mapped)
				if tag, ok := mapped["tag"].(string); ok {
					inboundTags = append(inboundTags, tag)
				}
			}
		default:
			// Unsupported inbound; skip.
		}
	}

	if len(singBoxInbounds) == 0 {
		return nil, errf("no supported inbound found (need VLESS+Reality or Shadowsocks)")
	}

	// --- Outbounds ---
	singBoxOutbounds := buildOutbounds(cfg)
	var outboundTags []string
	validOutbound := map[string]bool{}
	for _, o := range singBoxOutbounds {
		if tag, ok := o["tag"].(string); ok {
			outboundTags = append(outboundTags, tag)
			validOutbound[tag] = true
		}
	}

	// Convert outbounds to []any for a consistent map value type.
	outboundsAny := make([]any, len(singBoxOutbounds))
	for i, o := range singBoxOutbounds {
		outboundsAny[i] = o
	}

	// --- Routing ---
	routing, hasRemoteSets := buildRouting(cfg, validOutbound)

	experimental := map[string]any{
		"v2ray_api": map[string]any{
			"listen": statsListen,
			"stats": map[string]any{
				"enabled":   true,
				"inbounds":  inboundTags,
				"outbounds": outboundTags,
				"users":     statUserNames(vlessUsers, ssUsers),
			},
		},
		"clash_api": map[string]any{
			"external_controller": clashListen,
		},
	}
	if routing != nil && hasRemoteSets {
		experimental["cache_file"] = map[string]any{
			"enabled": true,
			"path":    resolveGeoCachePath(),
		}
	}

	config := map[string]any{
		"log": map[string]any{
			"level":     logLevel,
			"timestamp": true,
		},
		"inbounds":     singBoxInbounds,
		"outbounds":    outboundsAny,
		"experimental": experimental,
	}
	if routing != nil {
		config["route"] = routing
	}

	return &Result{
		Config:     config,
		InboundTag: primaryTag,
		Users:      vlessUsers,
		SsUsers:    ssUsers,
		ListenPort: primaryPort,
	}, nil
}

func userNames(users []VlessUser) []string {
	var out []string
	for _, u := range users {
		out = append(out, u.Name)
	}
	return out
}

// StatUserNames returns the unified user email list (VLESS + Shadowsocks 2022)
// tracked by the v2ray_api stats service.
func StatUserNames(vless []VlessUser, ss []SsUser) []string {
	return statUserNames(vless, ss)
}

// statUserNames returns the unified user email list (VLESS + Shadowsocks 2022)
// tracked by the v2ray_api stats service.
func statUserNames(vless []VlessUser, ss []SsUser) []string {
	out := make([]string, 0, len(vless)+len(ss))
	out = append(out, userNames(vless)...)
	for _, u := range ss {
		out = append(out, u.Name)
	}
	return out
}

func asArr(v any) []any {
	arr, _ := v.([]any)
	return arr
}

func asStrArr(v any) []string {
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	var out []string
	for _, it := range arr {
		if s, ok := it.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

func firstNonEmptyStr(vals ...string) string {
	for _, v := range vals {
		if v != "" {
			return v
		}
	}
	return ""
}

func toStringArray(v any) []string { return asStrArr(v) }

// UsersFromConfig extracts the VLESS user list from a panel config (used by
// the state store when a full config is pushed).
func UsersFromConfig(cfg map[string]any) []VlessUser {
	return buildVlessUsers(cfg, nil)
}

// SsUsersFromConfig extracts the Shadowsocks 2022 user list from a panel
// config (used by the state store when a full config is pushed).
func SsUsersFromConfig(cfg map[string]any) []SsUser {
	return buildSsUsers(cfg, nil)
}

// NormalizeFlow defaults an empty VLESS flow to xtls-rprx-vision.
func NormalizeFlow(flow string) string {
	return normalizeFlow(flow)
}

// buildVlessUsers collects VLESS users from the config's reality inbounds,
// or uses the provided desired set. Empty flow is normalized to vision.
func buildVlessUsers(cfg map[string]any, desired []VlessUser) []VlessUser {
	if desired != nil {
		out := make([]VlessUser, len(desired))
		for i, u := range desired {
			out[i] = u
			out[i].Flow = normalizeFlow(u.Flow)
		}
		return out
	}

	seen := map[string]VlessUser{}
	var order []string
	for _, ibAny := range asArr(cfg["inbounds"]) {
		ib, ok := ibAny.(map[string]any)
		if !ok {
			continue
		}
		stream, _ := ib["streamSettings"].(map[string]any)
		if ib["protocol"] != "vless" || stream == nil || stream["security"] != "reality" {
			continue
		}
		settings, _ := ib["settings"].(map[string]any)
		for _, cAny := range asArr(settings["clients"]) {
			c, ok := cAny.(map[string]any)
			if !ok {
				continue
			}
			id, _ := c["id"].(string)
			if id == "" {
				continue
			}
			name, _ := c["email"].(string)
			if name == "" {
				name = id
			}
			flow, _ := c["flow"].(string)
			if _, exists := seen[id]; !exists {
				order = append(order, id)
			}
			seen[id] = VlessUser{Name: name, UUID: id, Flow: normalizeFlow(flow)}
		}
	}

	out := make([]VlessUser, 0, len(order))
	for _, id := range order {
		out = append(out, seen[id])
	}
	return out
}

// buildSsUsers collects Shadowsocks 2022 users from the config's shadowsocks
// inbounds, or returns the desired set when non-nil.
func buildSsUsers(cfg map[string]any, desired []SsUser) []SsUser {
	if desired != nil {
		out := make([]SsUser, len(desired))
		copy(out, desired)
		return out
	}

	seen := map[string]SsUser{}
	var order []string
	for _, ibAny := range asArr(cfg["inbounds"]) {
		ib, ok := ibAny.(map[string]any)
		if !ok {
			continue
		}
		if ib["protocol"] != "shadowsocks" {
			continue
		}
		settings, _ := ib["settings"].(map[string]any)
		for _, cAny := range asArr(settings["clients"]) {
			c, ok := cAny.(map[string]any)
			if !ok {
				continue
			}
			pwd, _ := c["password"].(string)
			if pwd == "" {
				continue
			}
			name, _ := c["email"].(string)
			if name == "" {
				name = pwd
			}
			if _, exists := seen[name]; !exists {
				order = append(order, name)
			}
			seen[name] = SsUser{Name: name, Password: pwd}
		}
	}

	out := make([]SsUser, 0, len(order))
	for _, name := range order {
		out = append(out, seen[name])
	}
	return out
}

// mapVlessInbound maps one Xray VLESS+Reality inbound to sing-box.
func mapVlessInbound(ib map[string]any, users []VlessUser) map[string]any {
	stream, _ := ib["streamSettings"].(map[string]any)
	reality, _ := stream["realitySettings"].(map[string]any)

	privateKey, _ := reality["privateKey"].(string)
	serverNames := asStrArr(reality["serverNames"])
	if privateKey == "" || len(serverNames) == 0 {
		return nil
	}

	serverName := serverNames[0]
	dest, _ := reality["dest"].(string)
	if dest == "" {
		dest, _ = reality["target"].(string)
	}
	hsServer, hsPort := parseDest(dest, serverName)

	listen := resolveListen(ib["listen"])
	listenPort := 443
	if p, ok := ib["port"].(float64); ok && p > 0 {
		listenPort = int(p)
	}
	tag, _ := ib["tag"].(string)
	if tag == "" {
		tag = "vless-in"
	}

	return map[string]any{
		"type":        "vless",
		"tag":         tag,
		"listen":      listen,
		"listen_port": listenPort,
		"users":       users,
		"tls": map[string]any{
			"enabled":     true,
			"server_name": serverName,
			"reality": map[string]any{
				"enabled": true,
				"handshake": map[string]any{
					"server":      hsServer,
					"server_port": hsPort,
				},
				"private_key": privateKey,
				"short_id":    shortIDs(reality),
			},
		},
	}
}

func shortIDs(reality map[string]any) []string {
	ids := asStrArr(reality["shortIds"])
	if len(ids) > 0 {
		return ids
	}
	return []string{""}
}

func parseDest(dest, fallbackServer string) (string, int) {
	if dest == "" {
		return fallbackServer, 443
	}
	trimmed := strings.TrimSpace(dest)
	if host, portStr, err := net.SplitHostPort(trimmed); err == nil {
		var port int
		if n, scanErr := fmt.Sscanf(portStr, "%d", &port); scanErr == nil && n == 1 && port > 0 && port <= 65535 {
			return host, port
		}
		return host, 443
	}
	if strings.HasPrefix(trimmed, "[") && strings.HasSuffix(trimmed, "]") {
		return strings.TrimSuffix(strings.TrimPrefix(trimmed, "["), "]"), 443
	}
	if strings.Count(trimmed, ":") == 1 {
		if host, port, ok := strings.Cut(trimmed, ":"); ok {
			var value int
			if n, err := fmt.Sscanf(port, "%d", &value); err == nil && n == 1 && value > 0 && value <= 65535 {
				return host, value
			}
			return host, 443
		}
	}
	return trimmed, 443
}

// mapShadowsocksInbound maps an Xray SS inbound to sing-box, single-password
// or multi-user (clients). When useDesired is true, ssUsers is authoritative
// (multi-user, may be empty meaning "no users").
func mapShadowsocksInbound(ib map[string]any, ssUsers []SsUser, useDesired bool) map[string]any {
	settings, _ := ib["settings"].(map[string]any)
	method, _ := settings["method"].(string)
	if method == "" {
		return nil
	}
	password, _ := settings["password"].(string)
	clients := asArr(settings["clients"])

	listenPort := 8388
	if p, ok := ib["port"].(float64); ok && p > 0 {
		listenPort = int(p)
	}
	listen := resolveListen(ib["listen"])
	tag, _ := ib["tag"].(string)
	if tag == "" {
		tag = "ss-in"
	}

	var networks []string
	if netStr, ok := settings["network"].(string); ok && netStr != "" {
		for _, s := range strings.Split(netStr, ",") {
			if s = strings.TrimSpace(s); s != "" {
				networks = append(networks, s)
			}
		}
	}

	base := map[string]any{
		"type":        "shadowsocks",
		"tag":         tag,
		"listen":      listen,
		"listen_port": listenPort,
		"method":      method,
	}
	if len(networks) > 0 {
		base["network"] = networks
	}

	if useDesired {
		if len(ssUsers) > 0 {
			var users []any
			for _, u := range ssUsers {
				users = append(users, map[string]any{"name": u.Name, "password": u.Password})
			}
			if password == "" {
				return nil // shared PSK mandatory for sing-box multi-user SS2022
			}
			base["password"] = password
			base["users"] = users
			return base
		}
		// If desired SS users is empty, fall through to single-user mode if password is present
		if password != "" {
			base["password"] = password
			return base
		}
		return nil
	}

	if len(clients) > 0 {
		var users []any
		for _, cAny := range clients {
			c, ok := cAny.(map[string]any)
			if !ok {
				continue
			}
			pwd, _ := c["password"].(string)
			if pwd == "" {
				continue
			}
			name, _ := c["email"].(string)
			if name == "" {
				name = pwd
			}
			users = append(users, map[string]any{"name": name, "password": pwd})
		}
		if len(users) > 0 {
			if password == "" {
				return nil // shared PSK mandatory for sing-box multi-user SS2022
			}
			base["password"] = password
			base["users"] = users
			return base
		}
	}

	if password == "" {
		return nil
	}
	base["password"] = password
	return base
}

// buildOutbounds maps Xray outbounds to sing-box outbounds.
func buildOutbounds(cfg map[string]any) []map[string]any {
	var out []map[string]any
	seen := map[string]bool{}

	for _, obAny := range asArr(cfg["outbounds"]) {
		ob, ok := obAny.(map[string]any)
		if !ok {
			continue
		}
		proto, _ := ob["protocol"].(string)
		tag, _ := ob["tag"].(string)
		if tag == "" || seen[tag] {
			continue
		}
		seen[tag] = true

		switch proto {
		case "freedom":
			d := map[string]any{"type": "direct", "tag": tag}
			if settings, ok := ob["settings"].(map[string]any); ok {
				if ds, ok := settings["domainStrategy"].(string); ok {
					switch ds {
					case "UseIPv4":
						d["domain_strategy"] = "ipv4_only"
					case "UseIPv6":
						d["domain_strategy"] = "ipv6_only"
					case "PreferIPv4":
						d["domain_strategy"] = "prefer_ipv4"
					case "PreferIPv6":
						d["domain_strategy"] = "prefer_ipv6"
					}
				}
			}
			out = append(out, d)
		case "blackhole":
			out = append(out, map[string]any{"type": "block", "tag": tag})
		case "shadowsocks":
			settings, _ := ob["settings"].(map[string]any)
			method, _ := settings["method"].(string)
			password, _ := settings["password"].(string)
			address, _ := settings["address"].(string)
			if method == "" || address == "" {
				continue
			}
			serverPort := 8388
			if p, ok := settings["port"].(float64); ok && p > 0 {
				serverPort = int(p)
			}
			o := map[string]any{
				"type":        "shadowsocks",
				"tag":         tag,
				"server":      address,
				"server_port": serverPort,
				"method":      method,
				"password":    password,
			}
			if netStr, ok := settings["network"].(string); ok && netStr != "" {
				var networks []string
				for _, s := range strings.Split(netStr, ",") {
					if s = strings.TrimSpace(s); s != "" {
						networks = append(networks, s)
					}
				}
				if len(networks) > 0 {
					o["network"] = networks
				}
			}
			out = append(out, o)
		default:
			// skip unsupported outbound
		}
	}

	if !seen["direct"] {
		out = append(out, map[string]any{"type": "direct", "tag": "direct"})
	}
	return out
}

// buildRouting maps routing.rules to a sing-box route object, plus rule-sets.
// validOutbound is the set of outbound tags produced by buildOutbounds. Rules
// referencing any other tag (e.g. the Xray-internal "REMNAWAVE_API" service tag
// or an unsupported protocol) are dropped so sing-box never routes into a
// missing outbound (which would produce a runtime "outbound not found" and drop
// the connection).
func buildRouting(cfg map[string]any, validOutbound map[string]bool) (route map[string]any, hasRemoteSets bool) {
	routing, _ := cfg["routing"].(map[string]any)
	if routing == nil {
		return nil, false
	}
	rules := asArr(routing["rules"])
	if len(rules) == 0 {
		return nil, false
	}

	var outRules []any
	ruleSetTags := map[string]struct{ Kind, Name string }{}

	for _, rAny := range rules {
		r, ok := rAny.(map[string]any)
		if !ok {
			continue
		}
		outboundTag, _ := r["outboundTag"].(string)
		if outboundTag == "" || !validOutbound[outboundTag] {
			continue
		}

		rule := map[string]any{}

		if in := toStringArray(r["inboundTag"]); len(in) > 0 {
			rule["inbound"] = in
		}
		if proto := toStringArray(r["protocol"]); len(proto) > 0 {
			rule["protocol"] = proto
		}
		if network := toStringArray(r["network"]); len(network) > 0 {
			rule["network"] = network
		}
		if ports, ranges := splitPorts(r["port"]); len(ports) > 0 || len(ranges) > 0 {
			if len(ports) > 0 {
				rule["port"] = ports
			}
			if len(ranges) > 0 {
				rule["port_range"] = ranges
			}
		}
		if ports, ranges := splitPorts(r["sourcePort"]); len(ports) > 0 || len(ranges) > 0 {
			if len(ports) > 0 {
				rule["source_port"] = ports
			}
			if len(ranges) > 0 {
				rule["source_port_range"] = ranges
			}
		}
		if source := toStringArray(r["source"]); len(source) > 0 {
			rule["source_ip_cidr"] = source
		}
		if users := toStringArray(r["user"]); len(users) > 0 {
			rule["user"] = users
		}

		var domainSuffix, domainKeyword, ruleSetRefs []string
		for _, d := range toStringArray(r["domain"]) {
			switch {
			case strings.HasPrefix(d, "domain:"):
				domainSuffix = append(domainSuffix, strings.TrimPrefix(d, "domain:"))
			case strings.HasPrefix(d, "keyword:"):
				domainKeyword = append(domainKeyword, strings.TrimPrefix(d, "keyword:"))
			case strings.HasPrefix(d, "full:"):
				domain := strings.TrimPrefix(d, "full:")
				if domain != "" {
					rule["domain"] = appendString(rule["domain"], domain)
				}
			case strings.HasPrefix(d, "geosite:"):
				name := strings.TrimPrefix(d, "geosite:")
				if isValidGeoRuleSetName(name) {
					tag := "geosite-" + name
					ruleSetRefs = append(ruleSetRefs, tag)
					ruleSetTags[tag] = struct{ Kind, Name string }{Kind: "geosite", Name: name}
				}
			case strings.HasPrefix(d, "regexp:"):
				if regex := strings.TrimPrefix(d, "regexp:"); regex != "" {
					rule["domain_regex"] = appendString(rule["domain_regex"], regex)
				}
			default:
				domainSuffix = append(domainSuffix, d)
			}
		}
		if len(domainSuffix) > 0 {
			rule["domain_suffix"] = domainSuffix
		}
		if len(domainKeyword) > 0 {
			rule["domain_keyword"] = domainKeyword
		}

		for _, ip := range toStringArray(r["ip"]) {
			switch {
			case ip == "geoip:private":
				rule["ip_is_private"] = true
			case strings.HasPrefix(ip, "geoip:"):
				name := strings.TrimPrefix(ip, "geoip:")
				if isValidGeoRuleSetName(name) {
					tag := "geoip-" + name
					ruleSetRefs = append(ruleSetRefs, tag)
					ruleSetTags[tag] = struct{ Kind, Name string }{Kind: "geoip", Name: name}
				}
			default:
				if ip != "" {
					rule["ip_cidr"] = appendString(rule["ip_cidr"], ip)
				}
			}
		}
		if len(ruleSetRefs) > 0 {
			rule["rule_set"] = ruleSetRefs
		}

		if hasMatcher(rule) {
			rule["outbound"] = outboundTag
			outRules = append(outRules, rule)
		}
	}

	if len(outRules) == 0 {
		return nil, false
	}

	// Build rule_set declarations (remote default + local fallback).
	var ruleSetDecls []any
	geoDir := os.Getenv("SINGBOX_GEO_DIR")
	var tags []string
	for tag := range ruleSetTags {
		tags = append(tags, tag)
	}
	sort.Strings(tags)

	for _, tag := range tags {
		info := ruleSetTags[tag]
		localPath := ""
		if geoDir != "" {
			localPath = joinGeoPath(geoDir, tag+".srs")
		}
		if localPath != "" && fileExists(localPath) {
			ruleSetDecls = append(ruleSetDecls, map[string]any{
				"tag":    tag,
				"type":   "local",
				"format": "binary",
				"path":   localPath,
			})
		} else {
			hasRemoteSets = true
			ruleSetDecls = append(ruleSetDecls, map[string]any{
				"tag":             tag,
				"type":            "remote",
				"format":          "binary",
				"url":             geoRuleSetURL(info.Kind, info.Name),
				"update_interval": "24h",
			})
		}
	}

	// If any inbound has sniffing enabled or any routing rule matches domains/protocols,
	// inject a top-level `action: sniff` rule so sing-box peeks TLS/HTTP/QUIC headers
	// and populates metadata.Domain/Protocol (aligning with Xray-core's sniffing behavior).
	if shouldEnableSniffing(cfg, outRules) {
		outRules = append([]any{map[string]any{"action": "sniff"}}, outRules...)
	}

	route = map[string]any{
		"rules": outRules,
		"final": "direct",
	}
	if len(ruleSetDecls) > 0 {
		route["rule_set"] = ruleSetDecls
	}
	return route, hasRemoteSets
}

func hasMatcher(rule map[string]any) bool {
	for _, k := range []string{"inbound", "protocol", "network", "port", "port_range", "source_port", "source_port_range", "source_ip_cidr", "user", "domain", "domain_suffix", "domain_keyword", "domain_regex", "ip_cidr", "rule_set"} {
		if v, ok := rule[k].([]string); ok && len(v) > 0 {
			return true
		}
	}
	if v, ok := rule["ip_is_private"].(bool); ok && v {
		return true
	}
	return false
}

// shouldEnableSniffing reports whether a top-level `action: sniff` rule should be
// injected into sing-box route.rules to mirror Xray-core's inbound sniffing.
func shouldEnableSniffing(cfg map[string]any, rules []any) bool {
	// Check if any inbound in the panel config explicitly enabled sniffing.
	for _, ibAny := range asArr(cfg["inbounds"]) {
		ib, ok := ibAny.(map[string]any)
		if !ok {
			continue
		}
		if sniffing, ok := ib["sniffing"].(map[string]any); ok {
			if enabled, _ := sniffing["enabled"].(bool); enabled {
				return true
			}
		}
	}

	// Check if any routing rule matches domain, protocol or rule_set.
	for _, rAny := range rules {
		r, ok := rAny.(map[string]any)
		if !ok {
			continue
		}
		for _, k := range []string{"domain", "domain_suffix", "domain_keyword", "domain_regex", "rule_set", "protocol"} {
			if v, ok := r[k].([]string); ok && len(v) > 0 {
				return true
			}
		}
	}
	return false
}

func appendString(value any, item string) []string {
	items, _ := value.([]string)
	return append(items, item)
}

func stringOrStringArray(value any) []string {
	if s, ok := value.(string); ok && s != "" {
		return []string{s}
	}
	if n, ok := value.(float64); ok {
		return []string{fmt.Sprintf("%d", int(n))}
	}
	return toStringArray(value)
}

func splitPorts(value any) (ports, ranges []any) {
	for _, item := range stringOrStringArray(value) {
		for _, token := range strings.Split(item, ",") {
			token = strings.TrimSpace(token)
			if token == "" {
				continue
			}
			if strings.Contains(token, "-") {
				if validPortRange(token) {
					ranges = append(ranges, token)
				}
			} else {
				if port, err := strconv.Atoi(token); err == nil && port >= 1 && port <= 65535 {
					ports = append(ports, port)
				}
			}
		}
	}
	return ports, ranges
}

func validPortRange(value string) bool {
	parts := strings.Split(value, "-")
	if len(parts) != 2 {
		return false
	}
	start, errStart := strconv.Atoi(strings.TrimSpace(parts[0]))
	end, errEnd := strconv.Atoi(strings.TrimSpace(parts[1]))
	return errStart == nil && errEnd == nil && start >= 1 && end <= 65535 && start <= end
}

// isValidGeoRuleSetName validates that the rule set name consists solely of safe
// alphanumeric, hyphen, or underscore characters, mitigating path traversal.
func isValidGeoRuleSetName(name string) bool {
	if name == "" || len(name) > 64 {
		return false
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_') {
			return false
		}
	}
	return true
}

func geoRuleSetURL(kind, name string) string {
	if kind == "geosite" {
		return "https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-" + name + ".srs"
	}
	return "https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-" + name + ".srs"
}

func resolveGeoCachePath() string {
	base := os.Getenv("SINGBOX_GEO_DIR")
	if base != "" {
		return joinGeoPath(base, ".cache.db")
	}
	return "/var/lib/rnode/singbox/geo-cache.db"
}

func joinGeoPath(dir, name string) string {
	return strings.TrimRight(dir, "/") + "/" + name
}

func fileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}

// normalizeFlow defaults an empty VLESS flow to xtls-rprx-vision (this fork
// only supports vision).
func normalizeFlow(flow string) string {
	if flow != "" {
		return flow
	}
	return "xtls-rprx-vision"
}

// resolveListen rewrites 0.0.0.0 to :: for dual-stack (SINGBOX_LISTEN overrides).
func resolveListen(panelListen any) string {
	if override := os.Getenv("SINGBOX_LISTEN"); override != "" {
		return override
	}
	value, _ := panelListen.(string)
	if value == "" {
		value = "0.0.0.0"
	}
	if value == "0.0.0.0" {
		return "::"
	}
	return value
}
