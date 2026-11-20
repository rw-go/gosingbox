package singbox

import (
	"context"
	"net/netip"
	"strings"
	"testing"

	"github.com/rwnode/rwnode-gosingbox/internal/contract"
	"github.com/sagernet/sing-box/adapter"
	M "github.com/sagernet/sing/common/metadata"
	"github.com/sagernet/sing/service"
)

func TestManagementGuardOnNativeDirectOutbounds(t *testing.T) {
	for _, explicit := range []bool{false, true} {
		e := NewEngine(Options{StatsAddr: "127.0.0.2:6458", ClashAddr: "[::1]:9098"})
		cfg := map[string]any{
			"log": map[string]any{"disabled": true},
			"dns": map[string]any{"servers": []any{map[string]any{"type": "hosts", "tag": "test", "predefined": map[string]any{"mgmt.invalid": []string{"127.0.0.2", "::1"}}}}},
		}
		if explicit {
			cfg["outbounds"] = []any{map[string]any{"type": "direct", "tag": "explicit-direct"}}
		}
		if err := e.ApplyConfigForFormat(cfg, contract.SingBoxConfig); err != nil {
			t.Fatal(err)
		}
		t.Cleanup(e.Shutdown)
		guard, ok := service.FromContext[adapter.OutboundManager](e.ctx).Default().(*guardedDirect)
		if !ok {
			t.Fatalf("native direct did not install guard (explicit=%v)", explicit)
		}
		for _, address := range []string{"127.0.0.2:6458", "[::ffff:127.0.0.2]:6458", "[::1]:9098", "0.0.0.0:6458", "mgmt.invalid:9098"} {
			conn, err := guard.DialContext(context.Background(), "tcp", M.ParseSocksaddr(address))
			if conn != nil {
				conn.Close()
			}
			if err == nil || !strings.Contains(err.Error(), "reserved") {
				t.Fatalf("expected reserved destination for %s, got %v", address, err)
			}
		}
		host := M.ParseSocksaddr("example.invalid:6458")
		public := netip.MustParseAddr("192.0.2.1")
		if !guard.protects("tcp", 6458) || guard.protects("tcp", 8999) || guard.protects("udp", 6458) || checkManagementAddresses(host, []netip.Addr{public}) != nil {
			t.Fatal("guard blocked an unrelated address, port or protocol")
		}
		mixed := []netip.Addr{public, netip.MustParseAddr("::1")}
		if _, err := guard.DialParallelNetwork(e.ctx, "tcp", host, mixed, nil, nil, nil, 0); err == nil || !strings.Contains(err.Error(), "reserved") {
			t.Fatal("mixed DNS answers were not rejected before parallel dial")
		}
		if explicit {
			// A failed switch to the legacy format must restore the native registry.
			invalid := map[string]any{"log": map[string]any{"disabled": true}, "route": map[string]any{"final": "missing"}}
			if err := e.ApplyConfigForFormat(invalid, contract.XrayConfig); err == nil || !strings.Contains(err.Error(), "rolled back") {
				t.Fatalf("expected rollback during format switch, got %v", err)
			}
			if _, ok := service.FromContext[adapter.OutboundManager](e.ctx).Default().(*guardedDirect); !ok {
				t.Fatal("rollback lost native direct protection")
			}
		}
		e.Shutdown()
	}
}
