// Package nftables manages the Remnawave firewall table via the `nft` CLI.
// It mirrors the Node.js NftService (which uses nftables-napi) but talks to
// the kernel through the nft command instead of libnftnl, keeping the Go node
// CGO-free and dependency-light.
//
// If the nft binary is missing or the process lacks CAP_NET_ADMIN, the manager
// is "unavailable" and every operation reports accepted=false (the panel's
// plugin endpoint still returns a well-formed response).
package nftables

import (
	"fmt"
	"net"
	"os/exec"
	"strings"
	"sync"
)

const (
	tableName     = "remnanode"
	setTorrent    = "torrent-blocker"
	setIngress    = "ingress-filter-ip"
	setIngress6   = "ingress-filter-ip6"
	setEgress     = "egress-filter-ip"
	setEgress6    = "egress-filter-ip6"
	setEgressPort = "egress-filter-port"
)

// Manager wraps the nft CLI.
type Manager struct {
	mu        sync.Mutex
	bin       string
	available bool
}

// BlockEntry is a single IP block request (mirrors the panel's block-ips
// schema: {ip, timeout}).
type BlockEntry struct {
	IP      string `json:"ip"`
	Timeout int    `json:"timeout"`
}

// New probes for the nft binary and CAP_NET_ADMIN.
func New() *Manager {
	bin := "nft"
	if path, err := exec.LookPath(bin); err == nil {
		bin = path
	} else {
		return &Manager{bin: bin, available: false}
	}
	m := &Manager{bin: bin, available: true}
	// Probe capability by listing the ruleset; a non-root/CAP_NET_ADMIN process
	// will fail here.
	if err := m.run("list", "tables"); err != nil {
		m.available = false
	}
	return m
}

// Available reports whether nft is usable.
func (m *Manager) Available() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.available
}

func (m *Manager) run(args ...string) error {
	out, err := exec.Command(m.bin, args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("nft %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// CreateTable (re)creates the firewall table, base chains and sets. It is
// idempotent: the table is flushed first if it already exists.
func (m *Manager) CreateTable() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.available {
		return fmt.Errorf("nft unavailable")
	}

	m.dropSetIfExists()
	_ = m.run("add", "table", "inet", tableName)

	// Base chains: accept by default, drop only set members.
	_ = m.run("add", "chain", "inet", tableName, "input", "{ type filter hook input priority filter; policy accept; }")
	_ = m.run("add", "chain", "inet", tableName, "forward", "{ type filter hook forward priority filter; policy accept; }")
	_ = m.run("add", "chain", "inet", tableName, "output", "{ type filter hook output priority filter; policy accept; }")

	// Address sets (v4 + v6) for ingress/torrent/egress.
	for _, spec := range []struct {
		name string
		typ  string
	}{
		{setTorrent, "ipv4_addr"},
		{setTorrent + "6", "ipv6_addr"},
		{setIngress, "ipv4_addr"},
		{setIngress6, "ipv6_addr"},
		{setEgress, "ipv4_addr"},
		{setEgress6, "ipv6_addr"},
	} {
		_ = m.run("add", "set", "inet", tableName, spec.name, fmt.Sprintf("{ type %s; flags timeout; }", spec.typ))
	}

	// Ingress drop rules (input + forward) for torrent-blocker and ingress sets.
	for _, set := range []string{setTorrent, setTorrent + "6"} {
		_ = m.run("add", "rule", "inet", tableName, "input", ipLiteral(set)+" saddr @"+set+" drop")
		_ = m.run("add", "rule", "inet", tableName, "forward", ipLiteral(set)+" saddr @"+set+" drop")
	}
	for _, set := range []string{setIngress, setIngress6} {
		_ = m.run("add", "rule", "inet", tableName, "input", ipLiteral(set)+" saddr @"+set+" drop")
		_ = m.run("add", "rule", "inet", tableName, "forward", ipLiteral(set)+" saddr @"+set+" drop")
	}
	// Egress drop rules (output) for egress sets.
	for _, set := range []string{setEgress, setEgress6} {
		_ = m.run("add", "rule", "inet", tableName, "output", ipLiteral(set)+" daddr @"+set+" drop")
	}
	return nil
}

// ipLiteral returns "ip" for v4 sets and "ip6" for v6 sets.
func ipLiteral(set string) string {
	if strings.HasSuffix(set, "6") {
		return "ip6"
	}
	return "ip"
}

// DropSet removes the entire table (used before recreate).
func (m *Manager) dropSetIfExists() {
	_ = m.run("delete", "table", "inet", tableName)
}

// BlockIP adds an IP to the torrent-blocker set (with optional timeout
// seconds). It also removes the address from any previous entry.
func (m *Manager) BlockIP(ip string, timeoutSeconds int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.available {
		return fmt.Errorf("nft unavailable")
	}
	set := setFor(ip, setTorrent, setTorrent+"6")
	if set == "" {
		return fmt.Errorf("invalid ip: %q", ip)
	}
	element := "{" + ip
	if timeoutSeconds > 0 {
		element = fmt.Sprintf("%s timeout %ds", element, timeoutSeconds)
	}
	element += "}"
	return m.run("add", "element", "inet", tableName, set, element)
}

// UnblockIPs removes IPs from the torrent-blocker and ingress-filter sets.
func (m *Manager) UnblockIPs(ips []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.available {
		return fmt.Errorf("nft unavailable")
	}
	for _, ip := range ips {
		t := setFor(ip, setTorrent, setTorrent+"6")
		if t == "" {
			continue
		}
		_ = m.run("delete", "element", "inet", tableName, t, "{ "+ip+" }")
		i := setFor(ip, setIngress, setIngress6)
		_ = m.run("delete", "element", "inet", tableName, i, "{ "+ip+" }")
	}
	return nil
}

// AddIngressIPs adds IPs to the ingress-filter set (used by plugin sync).
func (m *Manager) AddIngressIPs(ips []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.available {
		return fmt.Errorf("nft unavailable")
	}
	for _, ip := range ips {
		set := setFor(ip, setIngress, setIngress6)
		if set == "" {
			continue
		}
		_ = m.run("add", "element", "inet", tableName, set, "{ "+ip+" }")
	}
	return nil
}

// setFor returns the v4 or v6 set name for an IP.
func setFor(ip, setV4, setV6 string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		return ""
	}
	if parsed.To4() != nil {
		return setV4
	}
	return setV6
}
