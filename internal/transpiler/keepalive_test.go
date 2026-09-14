package transpiler

import "testing"

func TestOutboundKeepAliveOptions(t *testing.T) {
	cfg := map[string]any{
		"outbounds": []any{
			map[string]any{
				"tag":      "ss-out",
				"protocol": "shadowsocks",
				"settings": map[string]any{
					"port":     8443,
					"method":   "2022-blake3-aes-256-gcm",
					"address":  "1.2.3.4",
					"password": "secretpassword",
				},
			},
			map[string]any{
				"tag":      "vless-out",
				"protocol": "vless",
				"settings": map[string]any{
					"port":    443,
					"address": "1.2.3.4",
					"id":      "00000000-0000-0000-0000-000000000000",
				},
			},
		},
	}
	outbounds := buildOutbounds(cfg)
	if len(outbounds) < 2 {
		t.Fatalf("expected at least 2 outbounds, got %d", len(outbounds))
	}
	for _, o := range outbounds {
		tag := o["tag"].(string)
		if tag != "ss-out" && tag != "vless-out" {
			continue
		}
		if o["tcp_keep_alive"] != "15s" {
			t.Errorf("[%s] expected tcp_keep_alive=15s, got %v", tag, o["tcp_keep_alive"])
		}
		if o["tcp_keep_alive_interval"] != "5s" {
			t.Errorf("[%s] expected tcp_keep_alive_interval=5s, got %v", tag, o["tcp_keep_alive_interval"])
		}
		if o["connect_timeout"] != "5s" {
			t.Errorf("[%s] expected connect_timeout=5s, got %v", tag, o["connect_timeout"])
		}
	}
}
