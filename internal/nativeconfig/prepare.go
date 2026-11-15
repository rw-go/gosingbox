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
	"strconv"
	"strings"

	"github.com/rwnode/rwnode-gosingbox/internal/state"
)

type Management struct {
	StatsAddress string
	ClashAddress string
	ClashSecret  string
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
	seen := map[string]bool{}
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
			options, ok := inbound["tls"].(map[string]any)
			if !ok || options["enabled"] != true {
				return nil, fmt.Errorf("inbound %q: AnyTLS requires TLS", tag)
			}
			if reality, ok := options["reality"].(map[string]any); ok && reality["enabled"] == true {
				return nil, fmt.Errorf("inbound %q: AnyTLS requires ordinary TLS", tag)
			}
		case "vless":
			if transport := inbound["transport"]; transport != nil {
				return nil, fmt.Errorf("inbound %q: managed VLESS currently supports TCP without a transport wrapper", tag)
			}
		case "shadowsocks":
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
			if _, present := inbound["users"]; !present {
				return nil, fmt.Errorf("inbound %q: managed Shadowsocks requires an explicit users array", tag)
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
		list, ok := users.([]any)
		if !ok {
			return nil, fmt.Errorf("inbound %q: users must be an array", tag)
		}
		if kind == "shadowsocks" {
			// sing-box selects a single-password server unless an empty list is marked
			// managed; it rejects managed=true combined with a nonempty user list.
			if len(list) == 0 {
				inbound["managed"] = true
			} else {
				delete(inbound, "managed")
			}
		}
		if options, ok := inbound["tls"].(map[string]any); ok && options["enabled"] == true {
			if err := checkCertificate(options); err != nil {
				return nil, fmt.Errorf("inbound %q: %w", tag, err)
			}
		}
	}
	users, err := state.FromConfig(config)
	if err != nil {
		return nil, err
	}
	if len(users) == 0 {
		return nil, fmt.Errorf("native config needs at least one managed inbound")
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
	// Preserve explicit inbound/outbound counters; include node-managed inbounds.
	tags := users.Tags()
	if existing, present := stats["inbounds"]; present {
		list, ok := existing.([]any)
		if !ok {
			return fmt.Errorf("stats.inbounds must be an array")
		}
		seen := map[string]bool{}
		for _, tag := range tags {
			seen[tag] = true
		}
		for _, value := range list {
			tag, ok := value.(string)
			if !ok {
				return fmt.Errorf("stats.inbounds entries must be strings")
			}
			if !seen[tag] {
				tags = append(tags, tag)
				seen[tag] = true
			}
		}
	}
	stats["inbounds"] = tags
	clash["external_controller"] = management.ClashAddress
	clash["secret"] = management.ClashSecret
	return nil
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
func checkCertificate(options map[string]any) error {
	if reality, ok := options["reality"].(map[string]any); ok && reality["enabled"] == true {
		return nil
	}
	// Match the core's provider precedence. Provider lifecycle and references
	// require an actual instance and remain subject to startup/rollback handling.
	if options["certificate_provider"] != nil || options["acme"] != nil {
		return nil
	}
	cert, certPresent, err := readPEM(options, "certificate")
	if err != nil {
		return err
	}
	key, keyPresent, err := readPEM(options, "key")
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
func readPEM(options map[string]any, field string) ([]byte, bool, error) {
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
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, true, fmt.Errorf("read TLS %s file: %w", field, err)
		}
		return data, true, nil
	}
	return nil, false, nil
}
