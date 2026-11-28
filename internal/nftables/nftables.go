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
	"strconv"
	"strings"
	"sync"
)

const (
	// DefaultTableName mirrors upstream remnawave/node NFTABLES_TABLE_NAME default.
	DefaultTableName = "remnanode"

	// MaxTableNameLen matches upstream remnawave/node config.schema.ts
	// (/^[A-Za-z_][A-Za-z0-9_-]{0,62}$/, 63 chars + NUL = 64 bytes).
	MaxTableNameLen = 63

	setTorrent    = "torrent-blocker"
	setIngress    = "ingress-filter-ip"
	setIngress6   = "ingress-filter-ip6"
	setEgress     = "egress-filter-ip"
	setEgress6    = "egress-filter-ip6"
	setEgressPort = "egress-filter-port"
)

// CommandRunner executes a single `nft` invocation and returns combined output.
type CommandRunner func(args ...string) ([]byte, error)

// Option configures a Manager at construction time.
type Option func(*options)

type options struct {
	tableName string
	runner    CommandRunner
}

// WithTableName sets a custom nftables inet table name (empty/whitespace falls
// back to DefaultTableName; invalid names cause New to return an error).
func WithTableName(name string) Option {
	return func(o *options) {
		o.tableName = name
	}
}

// WithCommandRunner overrides the underlying `nft` command executor (used by
// unit/controller tests so table operations can be verified without root).
func WithCommandRunner(fn CommandRunner) Option {
	return func(o *options) {
		o.runner = fn
	}
}

// ValidateTableName normalizes and validates an NFTABLES_TABLE_NAME value.
// Empty or whitespace-only input resolves to DefaultTableName ("remnanode").
// Non-empty values must match ^[A-Za-z_][A-Za-z0-9_-]{0,62}$ with no embedded
// or trailing newlines/metacharacters so injection into `nft` CLI or `nft -f -`
// scripts is impossible.
func ValidateTableName(raw string) (string, error) {
	if strings.TrimSpace(raw) == "" {
		return DefaultTableName, nil
	}
	if strings.ContainsAny(raw, "\r\n") {
		return "", fmt.Errorf("invalid NFTABLES_TABLE_NAME %q: newline characters are not allowed", raw)
	}
	name := strings.TrimSpace(raw)
	if !isValidTableIdentifier(name) {
		return "", fmt.Errorf(
			"invalid NFTABLES_TABLE_NAME %q: must start with a letter or underscore and contain only ASCII letters, digits, '_' or '-' (max %d chars)",
			raw, MaxTableNameLen,
		)
	}
	return name, nil
}

func isValidTableIdentifier(name string) bool {
	if len(name) == 0 || len(name) > MaxTableNameLen {
		return false
	}
	first := name[0]
	if !isASCIIAlpha(first) && first != '_' {
		return false
	}
	for i := 1; i < len(name); i++ {
		c := name[i]
		if !isASCIIAlpha(c) && !isASCIIDigit(c) && c != '_' && c != '-' {
			return false
		}
	}
	return true
}

func isASCIIAlpha(c byte) bool {
	return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z')
}

func isASCIIDigit(c byte) bool {
	return c >= '0' && c <= '9'
}

// Manager wraps the nft CLI.
type Manager struct {
	mu                 sync.Mutex
	bin                string
	tableName          string
	runner             CommandRunner
	available          bool
	acceptReplyTraffic bool
}

// BlockEntry is a single IP block request (mirrors the panel's block-ips
// schema: {ip, timeout}).
type BlockEntry struct {
	IP      string `json:"ip"`
	Timeout int    `json:"timeout"`
}

// New validates options and probes for the nft binary and CAP_NET_ADMIN.
// acceptReplyTraffic mirrors the official NFTABLES_ACCEPT_REPLY_TRAFFIC option:
// when true, the egress filter accepts established/related flows so reply
// traffic is not dropped.
func New(acceptReplyTraffic bool, opts ...Option) (*Manager, error) {
	var cfg options
	for _, opt := range opts {
		if opt != nil {
			opt(&cfg)
		}
	}
	tbl, err := ValidateTableName(cfg.tableName)
	if err != nil {
		return nil, err
	}

	bin := "nft"
	runner := cfg.runner
	if runner == nil {
		path, lookErr := exec.LookPath(bin)
		if lookErr != nil {
			return &Manager{
				bin:                bin,
				tableName:          tbl,
				available:          false,
				acceptReplyTraffic: acceptReplyTraffic,
			}, nil
		}
		bin = path
		runner = func(args ...string) ([]byte, error) {
			return exec.Command(bin, args...).CombinedOutput()
		}
	}

	m := &Manager{
		bin:                bin,
		tableName:          tbl,
		runner:             runner,
		available:          true,
		acceptReplyTraffic: acceptReplyTraffic,
	}
	// Probe capability by listing the ruleset; a non-root/CAP_NET_ADMIN process
	// will fail here.
	if err := m.run("list", "tables"); err != nil {
		m.available = false
	}
	return m, nil
}

// TableName returns the configured nftables inet table name.
func (m *Manager) TableName() string {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.tableName == "" {
		return DefaultTableName
	}
	return m.tableName
}

// Available reports whether nft is usable.
func (m *Manager) Available() bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.available
}

func (m *Manager) validatedTableLocked() (string, error) {
	if !isValidTableIdentifier(m.tableName) {
		return "", fmt.Errorf("invalid nftables table name: %q", m.tableName)
	}
	return m.tableName, nil
}

func (m *Manager) run(args ...string) error {
	if m.runner == nil {
		return fmt.Errorf("nft runner unavailable")
	}
	out, err := m.runner(args...)
	if err != nil {
		return fmt.Errorf("nft %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return nil
}

// CreateTable (re)creates the firewall table, base chains and sets. It is
// idempotent: the table is deleted first if it already exists.
func (m *Manager) CreateTable() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.available {
		return fmt.Errorf("nft unavailable")
	}
	tbl, err := m.validatedTableLocked()
	if err != nil {
		return err
	}

	m.dropTableIfExistsLocked(tbl)
	if err := m.run("add", "table", "inet", tbl); err != nil {
		return err
	}

	// Base chains: accept by default, drop only set members.
	for _, chain := range []string{"input", "forward", "output"} {
		if err := m.run("add", "chain", "inet", tbl, chain, "{ type filter hook "+chain+" priority filter; policy accept; }"); err != nil {
			return err
		}
	}

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
		if err := m.run("add", "set", "inet", tbl, spec.name, fmt.Sprintf("{ type %s; flags interval, timeout; }", spec.typ)); err != nil {
			return err
		}
	}

	// Egress port set (inet_service, used by tcp/udp dport lookups).
	if err := m.run("add", "set", "inet", tbl, setEgressPort, "{ type inet_service; flags interval; }"); err != nil {
		return err
	}

	// Ingress drop rules (input + forward) for torrent-blocker and ingress sets.
	for _, set := range []string{setTorrent, setTorrent + "6"} {
		if err := m.run("add", "rule", "inet", tbl, "input", ipLiteral(set)+" saddr @"+set+" drop"); err != nil {
			return err
		}
		if err := m.run("add", "rule", "inet", tbl, "forward", ipLiteral(set)+" saddr @"+set+" drop"); err != nil {
			return err
		}
	}
	for _, set := range []string{setIngress, setIngress6} {
		if err := m.run("add", "rule", "inet", tbl, "input", ipLiteral(set)+" saddr @"+set+" drop"); err != nil {
			return err
		}
		if err := m.run("add", "rule", "inet", tbl, "forward", ipLiteral(set)+" saddr @"+set+" drop"); err != nil {
			return err
		}
	}
	// Reply-traffic allow: accept established/related flows before the egress
	// drop rules (NFTABLES_ACCEPT_REPLY_TRAFFIC). Without this, dropping an
	// egress IP/port also tears down reply traffic of existing connections.
	if m.acceptReplyTraffic {
		if err := m.run("add", "rule", "inet", tbl, "output", "ct state established,related accept"); err != nil {
			return err
		}
	}

	// Egress drop rules (output) for egress sets.
	for _, set := range []string{setEgress, setEgress6} {
		if err := m.run("add", "rule", "inet", tbl, "output", ipLiteral(set)+" daddr @"+set+" drop"); err != nil {
			return err
		}
	}
	// Egress port drop rules (tcp + udp dport).
	if err := m.run("add", "rule", "inet", tbl, "output", "tcp dport @"+setEgressPort+" drop"); err != nil {
		return err
	}
	if err := m.run("add", "rule", "inet", tbl, "output", "udp dport @"+setEgressPort+" drop"); err != nil {
		return err
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

// dropTableIfExistsLocked removes the configured table before recreate.
func (m *Manager) dropTableIfExistsLocked(tbl string) {
	_ = m.run("delete", "table", "inet", tbl)
}

// BlockIP adds an IP to the torrent-blocker set (with optional timeout
// seconds).
func (m *Manager) BlockIP(ip string, timeoutSeconds int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.available {
		return fmt.Errorf("nft unavailable")
	}
	tbl, err := m.validatedTableLocked()
	if err != nil {
		return err
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
	return m.run("add", "element", "inet", tbl, set, element)
}

// UnblockIPs removes IPs from the torrent-blocker and ingress-filter sets.
func (m *Manager) UnblockIPs(ips []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.available {
		return fmt.Errorf("nft unavailable")
	}
	tbl, err := m.validatedTableLocked()
	if err != nil {
		return err
	}
	return m.removeIPsLocked(tbl, ips, setTorrent, setTorrent+"6", setIngress, setIngress6)
}

func (m *Manager) removeIPsLocked(tbl string, ips []string, primaryV4, primaryV6, secondaryV4, secondaryV6 string) error {
	sets := make(map[string][]string)
	seen := make(map[string]struct{})
	for _, ip := range ips {
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		primary := setFor(ip, primaryV4, primaryV6)
		if primary == "" {
			continue
		}
		secondary := setFor(ip, secondaryV4, secondaryV6)
		sets[primary] = append(sets[primary], ip)
		sets[secondary] = append(sets[secondary], ip)
	}

	var firstErr error
	for _, set := range []string{primaryV4, primaryV6, secondaryV4, secondaryV6} {
		elements := sets[set]
		if len(elements) == 0 {
			continue
		}
		if err := m.run("delete", "element", "inet", tbl, set, batchElements(elements)); err != nil {
			// A batch delete can fail when any member already expired. Retry each
			// element to retain the endpoint's idempotent behavior.
			for _, ip := range elements {
				if singleErr := m.run("delete", "element", "inet", tbl, set, "{ "+ip+" }"); singleErr != nil && !isMissingElementError(singleErr) && firstErr == nil {
					firstErr = singleErr
				}
			}
		}
	}
	return firstErr
}

func isMissingElementError(err error) bool {
	if err == nil {
		return false
	}
	message := err.Error()
	return strings.Contains(message, "No such file or directory") ||
		strings.Contains(message, "Could not process rule") && strings.Contains(message, "not found")
}

// AddIngressIPs adds IPs to the ingress-filter set (used by plugin sync).
func (m *Manager) AddIngressIPs(ips []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.available {
		return fmt.Errorf("nft unavailable")
	}
	tbl, err := m.validatedTableLocked()
	if err != nil {
		return err
	}
	return m.addIPsLocked(tbl, ips, setIngress, setIngress6)
}

// AddEgressIPs adds IPs to the egress-filter set (used by plugin sync).
func (m *Manager) AddEgressIPs(ips []string) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.available {
		return fmt.Errorf("nft unavailable")
	}
	tbl, err := m.validatedTableLocked()
	if err != nil {
		return err
	}
	return m.addIPsLocked(tbl, ips, setEgress, setEgress6)
}

func (m *Manager) addIPsLocked(tbl string, ips []string, setV4, setV6 string) error {
	sets := make(map[string][]string)
	seen := make(map[string]struct{})
	for _, ip := range ips {
		if _, ok := seen[ip]; ok {
			continue
		}
		seen[ip] = struct{}{}
		set := setFor(ip, setV4, setV6)
		if set != "" {
			sets[set] = append(sets[set], ip)
		}
	}

	var firstErr error
	for _, set := range []string{setV4, setV6} {
		elements := sets[set]
		if len(elements) == 0 {
			continue
		}
		if err := m.run("add", "element", "inet", tbl, set, batchElements(elements)); err != nil {
			// Keep the previous per-element semantics when a batch contains an
			// already-existing member or another partial failure.
			for _, ip := range elements {
				if singleErr := m.run("add", "element", "inet", tbl, set, "{ "+ip+" }"); singleErr != nil && firstErr == nil {
					firstErr = singleErr
				}
			}
		}
	}
	return firstErr
}

func batchElements(elements []string) string {
	return "{ " + strings.Join(elements, ", ") + " }"
}

// AddEgressPorts adds ports to the egress-filter port set.
func (m *Manager) AddEgressPorts(ports []int) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.available {
		return fmt.Errorf("nft unavailable")
	}
	tbl, err := m.validatedTableLocked()
	if err != nil {
		return err
	}
	if len(ports) == 0 {
		return nil
	}
	elems := make([]string, 0, len(ports))
	for _, p := range ports {
		if p < 1 || p > 65535 {
			continue
		}
		elems = append(elems, strconv.Itoa(p))
	}
	if len(elems) == 0 {
		return nil
	}
	return m.run("add", "element", "inet", tbl, setEgressPort, "{ "+strings.Join(elems, ", ")+" }")
}

// setFor returns the v4 or v6 set name for an IP.
func setFor(ip, setV4, setV6 string) string {
	parsed := net.ParseIP(ip)
	if parsed == nil {
		parsed, _, _ = net.ParseCIDR(ip)
	}
	if parsed == nil {
		return ""
	}
	if parsed.To4() != nil {
		return setV4
	}
	return setV6
}
