package transpiler

import (
	"encoding/json"
	"testing"
)

func TestFullVLESSConfigKeepsPerInboundUsers(t *testing.T) {
	inbound := func(tag, id string) map[string]any {
		return map[string]any{
			"protocol": "vless", "tag": tag, "port": 443,
			"settings":       map[string]any{"clients": []any{map[string]any{"email": id, "id": id}}},
			"streamSettings": map[string]any{"security": "reality", "realitySettings": map[string]any{"privateKey": "test-key", "serverNames": []string{"example.invalid"}}},
		}
	}
	raw, _ := json.Marshal(map[string]any{"inbounds": []any{inbound("a", "1"), inbound("b", "2")}})
	result, err := Transpile(raw, "127.0.0.1:0", "127.0.0.1:0", "error", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	for i, item := range result.Config["inbounds"].([]any) {
		ib := item.(map[string]any)
		users := ib["users"].([]VlessUser)
		want := []string{"1", "2"}[i]
		if len(users) != 1 || users[0].UUID != want {
			t.Fatalf("users leaked on %s: %+v", ib["tag"], users)
		}
	}
}
