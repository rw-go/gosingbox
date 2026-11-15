package singbox

import (
	"encoding/base64"
	"errors"
	"github.com/rwnode/rwnode-gosingbox/internal/state"
	"reflect"
	"testing"
)

func TestUserBatchRollbackIncludesFailingTarget(t *testing.T) {
	calls := []string{}
	changes := []userApply{
		{tag: "a", next: "new", previous: "old", apply: func(v any) error { calls = append(calls, "a:"+v.(string)); return nil }},
		{tag: "b", next: "new", previous: "old", apply: func(v any) error {
			calls = append(calls, "b:"+v.(string))
			if v == "new" {
				return errors.New("failure after mutation")
			}
			return nil
		}},
	}
	err, failed := applyUserChanges(changes)
	if err == nil || failed || !reflect.DeepEqual(calls, []string{"a:new", "b:new", "b:old", "a:old"}) {
		t.Fatalf("rollback=%v failed=%v err=%v", calls, failed, err)
	}
	changes[1].apply = func(any) error { return errors.New("unrecoverable") }
	if err, failed = applyUserChanges(changes); err == nil || !failed {
		t.Fatal("rollback failure hidden")
	}
}
func TestConfigBasePreservesRoutesAndTLS(t *testing.T) {
	a := map[string]any{"inbounds": []any{map[string]any{"type": "anytls", "tag": "a", "users": []any{map[string]any{"name": "1", "password": "old"}}, "tls": map[string]any{"enabled": true}}}}
	b := map[string]any{"inbounds": []any{map[string]any{"type": "anytls", "tag": "a", "users": []any{map[string]any{"name": "2", "password": "new"}}, "tls": map[string]any{"enabled": true}}}}
	if string(configBase(a)) != string(configBase(b)) {
		t.Fatal("user-only update changed base")
	}
	b["route"] = map[string]any{"final": "different"}
	if string(configBase(a)) == string(configBase(b)) {
		t.Fatal("route change ignored")
	}
	delete(b, "route")
	b["inbounds"].([]any)[0].(map[string]any)["tls"] = map[string]any{"enabled": false}
	if string(configBase(a)) == string(configBase(b)) {
		t.Fatal("TLS change ignored")
	}
}

func TestSS2022PrevalidationMatchesCipherKeyLengths(t *testing.T) {
	for _, tc := range []struct {
		method string
		length int
		valid  bool
	}{
		{"2022-blake3-aes-128-gcm", 16, true}, {"2022-blake3-aes-256-gcm", 16, false},
		{"2022-blake3-aes-256-gcm", 32, true}, {"2022-blake3-aes-256-gcm", 48, true},
	} {
		_, err := wireUsers(state.Inbound{Protocol: "shadowsocks22", Cipher: tc.method}, []state.User{{ID: "1", Credential: base64.StdEncoding.EncodeToString(make([]byte, tc.length))}})
		if (err == nil) != tc.valid {
			t.Fatalf("%s key length %d: %v", tc.method, tc.length, err)
		}
	}
}
