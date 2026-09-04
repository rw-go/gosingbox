package singbox

import (
	"context"
	"testing"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
)

func TestUpdateCurrentUsersLockedUpdatesMatchingInbound(t *testing.T) {
	vlessInbound := map[string]any{"type": "vless", "tag": "vless-in", "users": []any{}}
	ssInbound := map[string]any{"type": "shadowsocks", "tag": "ss-in", "users": []any{}}
	stats := map[string]any{"users": []string{}}
	e := &Engine{currentConfig: map[string]any{
		"inbounds": []any{vlessInbound, ssInbound},
		"experimental": map[string]any{
			"v2ray_api": map[string]any{"stats": stats},
		},
	}}

	vlessUsers := []option.VLESSUser{{Name: "vless@example.com", UUID: "uuid-1", Flow: "xtls-rprx-vision"}}
	e.updateCurrentUsersLocked("vless", "vless-in", vlessUsers)
	gotVless, ok := vlessInbound["users"].([]option.VLESSUser)
	if !ok || len(gotVless) != 1 || gotVless[0].Name != "vless@example.com" {
		t.Fatalf("vless rollback users = %#v", vlessInbound["users"])
	}

	ssUsers := []option.ShadowsocksUser{{Name: "ss@example.com", Password: "secret"}}
	e.updateCurrentUsersLocked("shadowsocks", "ss-in", ssUsers)
	gotSS, ok := ssInbound["users"].([]option.ShadowsocksUser)
	if !ok || len(gotSS) != 1 || gotSS[0].Name != "ss@example.com" {
		t.Fatalf("ss rollback users = %#v", ssInbound["users"])
	}
	gotStats, ok := stats["users"].([]string)
	if !ok || len(gotStats) != 2 || gotStats[0] != "vless@example.com" || gotStats[1] != "ss@example.com" {
		t.Fatalf("stats rollback users = %#v", stats["users"])
	}
}

func TestUpdateCurrentUsersLockedIgnoresOtherInbound(t *testing.T) {
	inbound := map[string]any{"type": "vless", "tag": "vless-in", "users": "original"}
	e := &Engine{currentConfig: map[string]any{"inbounds": []any{inbound}}}

	e.updateCurrentUsersLocked("vless", "other-in", []option.VLESSUser{})
	if got := inbound["users"]; got != "original" {
		t.Fatalf("unexpected rollback config mutation: %#v", got)
	}
}

type mockV2RayServer struct {
	adapter.V2RayServer
	users []string
}

func (m *mockV2RayServer) UpdateUsers(users []string) {
	m.users = users
}

func TestUpdateStatsUsers(t *testing.T) {
	mock := &mockV2RayServer{}
	ctx := service.ContextWith[adapter.V2RayServer](context.Background(), mock)
	e := &Engine{
		ctx:    ctx,
		online: true,
		box:    &box.Box{},
	}
	e.UpdateStatsUsers([]string{"user1@example.com", "user2@example.com"})
	if len(mock.users) != 2 || mock.users[0] != "user1@example.com" || mock.users[1] != "user2@example.com" {
		t.Fatalf("UpdateStatsUsers did not pass users: %#v", mock.users)
	}
}
