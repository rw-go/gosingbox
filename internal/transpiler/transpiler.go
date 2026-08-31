// Package transpiler translates a Remnawave panel Xray JSON config into a
// sing-box JSON config. It mirrors the mapping implemented in the Node.js
// version (src/modules/xray-core/singbox-transpiler.ts) exactly.
package transpiler

import (
	"encoding/json"
	"fmt"
	"os"
	"sort"
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
	for _, o := range singBoxOutbounds {
		if tag, ok := o["tag"].(string); ok {
			outboundTags = append(outboundTags, tag)
		}
	}

	// Convert outbounds to []any for a consistent map value type.
	outboundsAny := make([]any, len(singBoxOutbounds))
	for i, o := range singBoxOutbounds {
		outboundsAny[i] = o
	}

	// --- Routing ---
	routing, hasRemoteSets := buildRouting(cfg)

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
	if i := strings.LastIndex(trimmed, ":"); i > 0 {
		host := trimmed[:i]
		var port = 443
		if n, err := fmt.Sscanf(trimmed[i+1:], "%d", &port); err == nil && n == 1 && port > 0 && port <= 65535 {
			return host, port
		}
		return host, 443
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
			out = append(out, map[string]any{"type": "direct", "tag": tag})
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
func buildRouting(cfg map[string]any) (route map[string]any, hasRemoteSets bool) {
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
		if outboundTag == "" {
			continue
		}

		rule := map[string]any{}

		if in := toStringArray(r["inboundTag"]); len(in) > 0 {
			rule["inbound"] = in
		}
		if proto := toStringArray(r["protocol"]); len(proto) > 0 {
			rule["protocol"] = proto
		}

		var domainSuffix, domainKeyword, ruleSetRefs []string
		for _, d := range toStringArray(r["domain"]) {
			switch {
			case strings.HasPrefix(d, "domain:"):
				domainSuffix = append(domainSuffix, strings.TrimPrefix(d, "domain:"))
			case strings.HasPrefix(d, "keyword:"):
				domainKeyword = append(domainKeyword, strings.TrimPrefix(d, "keyword:"))
			case strings.HasPrefix(d, "full:"):
				domainSuffix = append(domainSuffix, strings.TrimPrefix(d, "full:"))
			case strings.HasPrefix(d, "geosite:"):
				name := strings.TrimPrefix(d, "geosite:")
				tag := "geosite-" + name
				ruleSetRefs = append(ruleSetRefs, tag)
				ruleSetTags[tag] = struct{ Kind, Name string }{Kind: "geosite", Name: name}
			case strings.HasPrefix(d, "regexp:"):
				// not mapped
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
				tag := "geoip-" + name
				ruleSetRefs = append(ruleSetRefs, tag)
				ruleSetTags[tag] = struct{ Kind, Name string }{Kind: "geoip", Name: name}
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
	for _, k := range []string{"inbound", "protocol", "domain_suffix", "domain_keyword", "rule_set"} {
		if v, ok := rule[k].([]string); ok && len(v) > 0 {
			return true
		}
	}
	if v, ok := rule["ip_is_private"].(bool); ok && v {
		return true
	}
	return false
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
