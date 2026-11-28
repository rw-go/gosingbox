package controller

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/rwnode/rwnode-gosingbox/internal/app"
	"github.com/rwnode/rwnode-gosingbox/internal/nftables"
	"github.com/rwnode/rwnode-gosingbox/internal/singbox"
	"github.com/rwnode/rwnode-gosingbox/internal/state"
)

func TestAppNewCheckedRejectsInvalidNftablesTableName(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	_, err := app.NewChecked(
		logger,
		singbox.NewEngine(singbox.Options{}),
		state.New(),
		5000,
		false,
		app.WithNftablesTableName("bad\n}"),
	)
	if err == nil {
		t.Fatal("NewChecked accepted invalid table name")
	}
}

func TestPluginEndpointsPropagateCustomNftablesTableName(t *testing.T) {
	const customTable = "custom_rw_table"
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))

	var calls [][]string
	a, err := app.NewChecked(
		logger,
		singbox.NewEngine(singbox.Options{}),
		state.New(),
		5000,
		true, // NFTABLES_ACCEPT_REPLY_TRAFFIC
		app.WithNftablesTableName(customTable),
		app.WithNftablesOptions(nftables.WithCommandRunner(func(args ...string) ([]byte, error) {
			calls = append(calls, append([]string(nil), args...))
			return nil, nil
		})),
	)
	if err != nil {
		t.Fatalf("NewChecked: %v", err)
	}
	t.Cleanup(a.Stop)

	mux := http.NewServeMux()
	NewPlugin(a, logger).Router(mux)

	postAccepted := func(path, body string) {
		t.Helper()
		rec := httptest.NewRecorder()
		mux.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, path, strings.NewReader(body)))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s status = %d, body = %s", path, rec.Code, rec.Body.String())
		}
		var env struct {
			Response struct {
				Accepted bool `json:"accepted"`
			} `json:"response"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &env); err != nil {
			t.Fatalf("%s decode: %v", path, err)
		}
		if !env.Response.Accepted {
			t.Fatalf("%s accepted = false, body = %s", path, rec.Body.String())
		}
	}

	// Reset recorded startup commands so each controller phase can be inspected cleanly.
	if len(calls) < 2 {
		t.Fatalf("expected startup probe + CreateTable calls, got %#v", calls)
	}
	calls = nil

	// 1. Full plugin sync (sharedLists + ingress + egress IPs/ports + reply traffic).
	postAccepted("/node/plugin/sync", `{
		"plugin": {
			"uuid": "00000000-0000-0000-0000-000000000001",
			"name": "fw",
			"config": {
				"sharedLists": [
					{"type": "ipList", "name": "ext:blocked", "items": ["192.0.2.0/24"]}
				],
				"ingressFilter": {"enabled": true, "blockedIps": ["ext:blocked", "2001:db8::1"]},
				"egressFilter": {"enabled": true, "blockedIps": ["203.0.113.5"], "blockedPorts": [25, 587]}
			}
		}
	}`)

	// 2. Torrent-blocker IP block + unblock endpoints.
	postAccepted("/node/plugin/nftables/block-ips", `{"ips":[{"ip":"198.51.100.9","timeout":120}]}`)
	postAccepted("/node/plugin/nftables/unblock-ips", `{"ips":["198.51.100.9"]}`)

	// 3. Empty plugin push (plugin == null) must recreate the custom table, not "remnanode".
	callsBeforeNullSync := len(calls)
	postAccepted("/node/plugin/sync", `{"plugin":null}`)
	if len(calls) <= callsBeforeNullSync {
		t.Fatal("expected plugin == null sync to recreate custom nftables table")
	}
	if got := strings.Join(calls[callsBeforeNullSync], " "); got != "delete table inet "+customTable {
		t.Fatalf("first command of plugin == null recreate = %q, want delete table inet %s", got, customTable)
	}

	// 4. Explicit /node/plugin/nftables/recreate-tables endpoint.
	callsBeforeRecreate := len(calls)
	postAccepted("/node/plugin/nftables/recreate-tables", `{}`)
	if len(calls) <= callsBeforeRecreate {
		t.Fatal("expected recreate-tables to execute nft commands")
	}

	// Every single command across all endpoints must target custom_rw_table and never remnanode.
	for i, args := range calls {
		joined := strings.Join(args, " ")
		if strings.Contains(joined, nftables.DefaultTableName) {
			t.Fatalf("call[%d] referenced default table %q instead of %q: %v", i, nftables.DefaultTableName, customTable, args)
		}
		if len(args) < 4 || args[2] != "inet" || args[3] != customTable {
			t.Fatalf("call[%d] did not target inet %s: %v", i, customTable, args)
		}
	}
}
