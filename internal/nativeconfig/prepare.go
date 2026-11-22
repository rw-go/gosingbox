// Package nativeconfig prepares native sing-box input without Xray translation.
// It owns only managed users and the node's local management API settings.
package nativeconfig

import (
	"bytes"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/rwnode/rwnode-gosingbox/internal/state"
)

var (
	defaultCacheDirs = []string{"/var/lib/gosingbox"}
	defaultCertDirs  = []string{
		"/etc/gosingbox",
		"/var/lib/gosingbox",
		"/etc/ssl",
		"/etc/letsencrypt",
		"/etc/pki",
		"/tls",
	}
)

type Management struct {
	StatsAddress     string
	ClashAddress     string
	ClashSecret      string
	AllowedCacheDirs []string
	AllowedCertDirs  []string
}
type Prepared struct {
	Config map[string]any
	Users  state.Snapshot
}

func Decode(raw []byte) (map[string]any, error) {
	if !json.Valid(raw) {
		return nil, fmt.Errorf("native config must be valid JSON")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var config map[string]any
	if err := decoder.Decode(&config); err != nil || config == nil {
		return nil, fmt.Errorf("native config must be a JSON object")
	}
	return config, nil
}

func Prepare(raw []byte, management Management) (*Prepared, error) {
	config, err := Decode(raw)
	if err != nil {
		return nil, err
	}
	inbounds, ok := config["inbounds"].([]any)
	if !ok || len(inbounds) == 0 {
		return nil, fmt.Errorf("native config needs at least one managed inbound")
	}
	for _, field := range []string{"endpoints", "services"} {
		if value, present := config[field]; present {
			list, ok := value.([]any)
			if !ok || len(list) != 0 {
				return nil, fmt.Errorf("native %s are not managed by this node", field)
			}
		}
	}
	if value, present := config["log"]; present {
		logCfg, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("log must be an object")
		}
		if out, hasOutput := logCfg["output"]; hasOutput && out != nil && out != "" {
			return nil, fmt.Errorf("native log.output is not managed by this node")
		}
	}
	seen := map[string]bool{}
	hasPrimaryInbound := false
	for _, value := range inbounds {
		inbound, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("native inbound must be an object")
		}
		tag, _ := inbound["tag"].(string)
		if tag == "" || seen[tag] {
			return nil, fmt.Errorf("native inbound tags must be nonempty and unique")
		}
		seen[tag] = true
		kind, _ := inbound["type"].(string)
		switch kind {
		case "anytls":
			hasPrimaryInbound = true
			options, ok := inbound["tls"].(map[string]any)
			if !ok || options["enabled"] != true {
				return nil, fmt.Errorf("inbound %q: AnyTLS requires TLS", tag)
			}
			if reality, ok := options["reality"].(map[string]any); ok && reality["enabled"] == true {
				return nil, fmt.Errorf("inbound %q: AnyTLS requires ordinary TLS", tag)
			}
		case "vless":
			hasPrimaryInbound = true
			if transport := inbound["transport"]; transport != nil {
				return nil, fmt.Errorf("inbound %q: managed VLESS currently supports TCP without a transport wrapper", tag)
			}
		case "shadowsocks":
			hasPrimaryInbound = true
			if value, present := inbound["managed"]; present {
				if _, ok := value.(bool); !ok {
					return nil, fmt.Errorf("inbound %q: managed must be a boolean", tag)
				}
			}
			method, _ := inbound["method"].(string)
			minimum := 32
			switch method {
			case "2022-blake3-aes-128-gcm":
				minimum = 16
			case "2022-blake3-aes-256-gcm":
			default:
				return nil, fmt.Errorf("inbound %q: unsupported managed Shadowsocks cipher", tag)
			}
			if value, present := inbound["destinations"]; present {
				if list, ok := value.([]any); !ok || len(list) > 0 {
					return nil, fmt.Errorf("inbound %q: Shadowsocks destinations cannot be managed", tag)
				}
			}
			password, _ := inbound["password"].(string)
			key, err := base64.StdEncoding.DecodeString(password)
			if err != nil || len(key) < minimum {
				return nil, fmt.Errorf("inbound %q: invalid Shadowsocks server key", tag)
			}
			var ssUsers []any
			if rawUsers, present := inbound["users"]; present {
				list, ok := rawUsers.([]any)
				if !ok {
					return nil, fmt.Errorf("inbound %q: users must be an array", tag)
				}
				ssUsers = list
			}
			delete(inbound, "managed")
			if len(ssUsers) == 0 {
				// Unified SS2022 password rule: 0 bound users always runs in
				// single-user PSK relay mode (omitting users and managed).
				delete(inbound, "users")
				continue
			}
		case "direct":
			listen, _ := inbound["listen"].(string)
			if ip := net.ParseIP(listen); ip == nil || !ip.IsLoopback() {
				return nil, fmt.Errorf("inbound %q: auxiliary direct listener must be loopback", tag)
			}
			if _, present := inbound["users"]; present {
				return nil, fmt.Errorf("inbound %q: auxiliary direct listener cannot contain users", tag)
			}
			continue
		default:
			return nil, fmt.Errorf("inbound %q: protocol %q is not managed", tag, kind)
		}
		users, present := inbound["users"]
		if !present {
			users = []any{}
			inbound["users"] = users
		}
		if _, ok := users.([]any); !ok {
			return nil, fmt.Errorf("inbound %q: users must be an array", tag)
		}
		if options, ok := inbound["tls"].(map[string]any); ok && options["enabled"] == true {
			if err := checkCertificate(options, management.certDirs()); err != nil {
				return nil, fmt.Errorf("inbound %q: %w", tag, err)
			}
		}
	}
	if !hasPrimaryInbound {
		return nil, fmt.Errorf("native config needs at least one managed inbound")
	}
	users, err := state.FromConfig(config)
	if err != nil {
		return nil, err
	}
	if err = injectManagement(config, users, management); err != nil {
		return nil, err
	}
	return &Prepared{Config: config, Users: users}, nil
}

func injectManagement(config map[string]any, users state.Snapshot, management Management) error {
	if err := localAddress(management.StatsAddress); err != nil {
		return fmt.Errorf("stats address: %w", err)
	}
	if err := localAddress(management.ClashAddress); err != nil {
		return fmt.Errorf("clash address: %w", err)
	}
	if management.StatsAddress == management.ClashAddress {
		return fmt.Errorf("management listeners must use distinct addresses")
	}
	if management.ClashSecret == "" {
		return fmt.Errorf("clash management secret is required")
	}
	experimental, err := object(config, "experimental")
	if err != nil {
		return err
	}
	if value, present := experimental["cache_file"]; present {
		cacheCfg, ok := value.(map[string]any)
		if !ok {
			return fmt.Errorf("cache_file must be an object")
		}
		if p, hasPath := cacheCfg["path"]; hasPath && p != nil && p != "" {
			cachePath, ok := p.(string)
			if !ok {
				return fmt.Errorf("cache_file.path must be a string")
			}
			if err := validateCacheFilePath(cachePath, management.cacheDirs()); err != nil {
				return err
			}
		}
	}
	v2ray, err := object(experimental, "v2ray_api")
	if err != nil {
		return err
	}
	stats, err := object(v2ray, "stats")
	if err != nil {
		return err
	}
	clash, err := object(experimental, "clash_api")
	if err != nil {
		return err
	}
	v2ray["listen"] = management.StatsAddress
	stats["enabled"] = true
	stats["users"] = users.Names()
	// Include 0-user single-password SS2022 relays in node traffic, but never in personal usage.
	tags := users.Tags()
	seenTags := make(map[string]bool, len(tags))
	for _, tag := range tags {
		seenTags[tag] = true
	}
	for _, value := range config["inbounds"].([]any) {
		inbound := value.(map[string]any)
		if inbound["type"] == "shadowsocks" {
			tag, _ := inbound["tag"].(string)
			if _, hasUsers := inbound["users"]; !hasUsers && inbound["managed"] != true && tag != "" && !seenTags[tag] {
				tags = append(tags, tag)
				seenTags[tag] = true
			}
		}
	}
	tags, err = mergeStatTags(tags, stats["inbounds"], "stats.inbounds")
	if err != nil {
		return err
	}
	stats["inbounds"] = tags

	outboundTags, err := collectOutboundStatTags(config)
	if err != nil {
		return err
	}
	outboundTags, err = mergeStatTags(outboundTags, stats["outbounds"], "stats.outbounds")
	if err != nil {
		return err
	}
	stats["outbounds"] = outboundTags

	delete(clash, "external_ui")
	delete(clash, "external_ui_download_url")
	delete(clash, "external_ui_download_detour")
	clash["external_controller"] = management.ClashAddress
	clash["secret"] = management.ClashSecret
	return nil
}

func collectOutboundStatTags(config map[string]any) ([]string, error) {
	rawOutbounds, present := config["outbounds"]
	if !present {
		return []string{"direct"}, nil
	}
	list, ok := rawOutbounds.([]any)
	if !ok {
		return nil, fmt.Errorf("native outbounds must be an array")
	}
	if len(list) == 0 {
		return []string{"direct"}, nil
	}
	tags := make([]string, 0, len(list))
	seen := map[string]bool{}
	for i, item := range list {
		outbound, ok := item.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("native outbound must be an object")
		}
		kind, _ := outbound["type"].(string)
		if kind == "block" || kind == "dns" {
			continue
		}
		tag, _ := outbound["tag"].(string)
		if tag == "" {
			// Match sing-box box.go outbound initialization: untagged outbounds are
			// named by their zero-based index ("0", "1", ...).
			tag = strconv.Itoa(i)
		}
		if !seen[tag] {
			tags = append(tags, tag)
			seen[tag] = true
		}
	}
	return tags, nil
}

func mergeStatTags(base []string, existing any, field string) ([]string, error) {
	if existing == nil {
		return base, nil
	}
	list, ok := existing.([]any)
	if !ok {
		return nil, fmt.Errorf("%s must be an array", field)
	}
	seen := make(map[string]bool, len(base))
	for _, tag := range base {
		seen[tag] = true
	}
	for _, value := range list {
		tag, ok := value.(string)
		if !ok {
			return nil, fmt.Errorf("%s entries must be strings", field)
		}
		if tag != "" && !seen[tag] {
			base = append(base, tag)
			seen[tag] = true
		}
	}
	return base, nil
}
func object(parent map[string]any, key string) (map[string]any, error) {
	if value, present := parent[key]; present {
		result, ok := value.(map[string]any)
		if !ok {
			return nil, fmt.Errorf("%s must be an object", key)
		}
		return result, nil
	}
	result := map[string]any{}
	parent[key] = result
	return result, nil
}
func localAddress(address string) error {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return fmt.Errorf("must be a loopback IP and port")
	}
	ip := net.ParseIP(host)
	number, err := strconv.Atoi(port)
	if ip == nil || !ip.IsLoopback() || err != nil || number < 1 || number > 65535 {
		return fmt.Errorf("must be a loopback IP and nonzero port")
	}
	return nil
}
func (m Management) cacheDirs() []string {
	dirs := append([]string(nil), defaultCacheDirs...)
	if geo := os.Getenv("SINGBOX_GEO_DIR"); filepath.IsAbs(geo) && geo == filepath.Clean(geo) {
		dirs = append(dirs, filepath.Dir(geo), geo)
	}
	dirs = append(dirs, m.AllowedCacheDirs...)
	return dirs
}

func (m Management) certDirs() []string {
	dirs := append([]string(nil), defaultCertDirs...)
	dirs = append(dirs, m.AllowedCertDirs...)
	return dirs
}

func hasAllowedPrefix(path string, dirs []string) bool {
	for _, rawDir := range dirs {
		dir := filepath.Clean(rawDir)
		if !filepath.IsAbs(dir) || dir == "/" {
			continue
		}
		if path == dir || strings.HasPrefix(path, dir+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

func resolveWithExistingAncestor(path string) (string, error) {
	cur := filepath.Clean(path)
	var tail []string
	for {
		resolved, err := filepath.EvalSymlinks(cur)
		if err == nil {
			for i := len(tail) - 1; i >= 0; i-- {
				resolved = filepath.Join(resolved, tail[i])
			}
			return resolved, nil
		}
		if !os.IsNotExist(err) {
			return "", err
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return cur, nil
		}
		tail = append(tail, filepath.Base(cur))
		cur = parent
	}
}

func resolvedAllowedDirs(dirs []string) []string {
	out := make([]string, 0, len(dirs)*2)
	for _, d := range dirs {
		clean := filepath.Clean(d)
		if !filepath.IsAbs(clean) || clean == "/" {
			continue
		}
		out = append(out, clean)
		if realDir, err := resolveWithExistingAncestor(clean); err == nil && realDir != clean && realDir != "/" {
			out = append(out, realDir)
		}
	}
	return out
}

func validateCacheFilePath(path string, allowed []string) error {
	if !filepath.IsAbs(path) || path != filepath.Clean(path) {
		return fmt.Errorf("native cache_file.path must be a clean absolute path")
	}
	base := filepath.Base(path)
	if !strings.HasSuffix(base, ".db") || len(base) <= len(".db") {
		return fmt.Errorf("native cache_file.path must be a .db file inside /var/lib/gosingbox")
	}
	dirs := resolvedAllowedDirs(allowed)
	if !hasAllowedPrefix(path, dirs) {
		return fmt.Errorf("native cache_file.path must reside under /var/lib/gosingbox")
	}
	if info, err := os.Lstat(path); err == nil {
		if !info.Mode().IsRegular() {
			return fmt.Errorf("native cache_file.path must reference a regular file")
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("invalid native cache_file.path")
	}
	realPath, err := resolveWithExistingAncestor(path)
	if err != nil || !hasAllowedPrefix(realPath, dirs) {
		return fmt.Errorf("native cache_file.path escapes managed directory")
	}
	for _, dir := range dirs {
		if realPath == dir {
			return fmt.Errorf("native cache_file.path must be a file, not a directory")
		}
	}
	return nil
}

func checkCertificate(options map[string]any, certDirs []string) error {
	if reality, ok := options["reality"].(map[string]any); ok && reality["enabled"] == true {
		return nil
	}
	// Match the core's provider precedence. Provider lifecycle and references
	// require an actual instance and remain subject to startup/rollback handling.
	if acmeRaw, hasAcme := options["acme"]; hasAcme && acmeRaw != nil {
		acme, ok := acmeRaw.(map[string]any)
		if !ok {
			return fmt.Errorf("TLS acme must be an object")
		}
		if dir, hasDir := acme["data_directory"]; hasDir && dir != nil && dir != "" {
			return fmt.Errorf("TLS acme.data_directory is not managed by this node")
		}
		return nil
	}
	if options["certificate_provider"] != nil {
		return nil
	}
	cert, certPresent, err := readPEM(options, "certificate", certDirs)
	if err != nil {
		return err
	}
	key, keyPresent, err := readPEM(options, "key", certDirs)
	if err != nil {
		return err
	}
	if !certPresent && !keyPresent {
		return fmt.Errorf("TLS certificate and key are required")
	}
	if _, err = tls.X509KeyPair(cert, key); err != nil {
		return fmt.Errorf("invalid TLS certificate/key: %w", err)
	}
	return nil
}
func readPEM(options map[string]any, field string, certDirs []string) ([]byte, bool, error) {
	if value, present := options[field]; present {
		switch value := value.(type) {
		case string:
			return []byte(value), true, nil
		case []any:
			if len(value) == 0 {
				break // Empty inline list falls back to the file, as in the core.
			}
			lines := make([]string, 0, len(value))
			for _, line := range value {
				str, ok := line.(string)
				if !ok {
					return nil, true, fmt.Errorf("TLS %s must contain PEM strings", field)
				}
				lines = append(lines, str)
			}
			return []byte(strings.Join(lines, "\n")), true, nil
		case nil:
			break
		default:
			return nil, true, fmt.Errorf("TLS %s must contain PEM strings", field)
		}
	}
	if value, present := options[field+"_path"]; present {
		path, ok := value.(string)
		if !ok || path == "" {
			return nil, true, fmt.Errorf("TLS %s_path must be nonempty", field)
		}
		if !filepath.IsAbs(path) || path != filepath.Clean(path) {
			return nil, true, fmt.Errorf("TLS %s_path must be a clean absolute path", field)
		}
		dirs := resolvedAllowedDirs(certDirs)
		if !hasAllowedPrefix(path, dirs) {
			return nil, true, fmt.Errorf("TLS %s_path is outside allowed certificate directories", field)
		}
		realPath, err := filepath.EvalSymlinks(path)
		if err != nil {
			return nil, true, fmt.Errorf("read TLS %s file", field)
		}
		if !hasAllowedPrefix(realPath, dirs) {
			return nil, true, fmt.Errorf("TLS %s_path resolves outside allowed certificate directories", field)
		}
		info, err := os.Stat(realPath)
		if err != nil || !info.Mode().IsRegular() {
			return nil, true, fmt.Errorf("read TLS %s file", field)
		}
		data, err := os.ReadFile(realPath)
		if err != nil {
			return nil, true, fmt.Errorf("read TLS %s file", field)
		}
		return data, true, nil
	}
	return nil, false, nil
}
