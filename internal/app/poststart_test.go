package app

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/rwnode/rwnode-gosingbox/internal/singbox"
)

func newTestApp() *App {
	return New(
		slog.New(slog.NewTextHandler(io.Discard, nil)),
		singbox.NewEngine(singbox.Options{}),
		nil,
		0,
		false,
	)
}

func TestSyncPluginsCachesPostStartWebhook(t *testing.T) {
	a := newTestApp()
	a.SyncPlugins(PluginSpec{PostStart: &PostStartSpec{
		Enabled: true,
		Webhook: &PostStartWebhookSpec{Enabled: true, URL: "http://example.test/hook"},
	}})
	a.postMu.Lock()
	webhook := a.postWebhook
	a.postMu.Unlock()
	if webhook == nil || !webhook.Enabled || webhook.URL != "http://example.test/hook" {
		t.Fatalf("postStart webhook not cached: %#v", webhook)
	}

	a.SyncPlugins(PluginSpec{PostStart: &PostStartSpec{Enabled: false}})
	a.postMu.Lock()
	webhook = a.postWebhook
	a.postMu.Unlock()
	if webhook != nil {
		t.Fatalf("disabled postStart must clear the webhook: %#v", webhook)
	}
}

func TestRunPostStartSendsCoreStartedWebhook(t *testing.T) {
	received := make(chan map[string]any, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Errorf("decode webhook body: %v", err)
		}
		if r.Header.Get("Content-Type") != "application/json" {
			t.Errorf("content-type = %q", r.Header.Get("Content-Type"))
		}
		received <- body
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	a := newTestApp()
	a.SyncPlugins(PluginSpec{PostStart: &PostStartSpec{
		Enabled: true,
		Webhook: &PostStartWebhookSpec{Enabled: true, URL: server.URL},
	}})

	a.RunPostStart(json.RawMessage(`{"name":"node-1","uuid":"abc","id":7,"tags":["a"],"countryCode":"HK"}`))

	select {
	case body := <-received:
		if body["scope"] != "service" || body["event"] != "service.core_started" {
			t.Fatalf("unexpected payload: %#v", body)
		}
		if body["timestamp"] == "" {
			t.Fatal("missing timestamp")
		}
		metadata, ok := body["metadata"].(map[string]any)
		if !ok || metadata["name"] != "node-1" || metadata["uuid"] != "abc" {
			t.Fatalf("metadata not forwarded: %#v", body["metadata"])
		}
	case <-time.After(2 * time.Second):
		t.Fatal("webhook was not delivered")
	}
}

func TestRunPostStartSkipsWhenDisabled(t *testing.T) {
	called := false
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	a := newTestApp()
	a.RunPostStart(nil)
	a.SyncPlugins(PluginSpec{})
	a.RunPostStart(json.RawMessage(`{}`))
	a.SyncPlugins(PluginSpec{PostStart: &PostStartSpec{
		Enabled: true,
		Webhook: &PostStartWebhookSpec{Enabled: false, URL: server.URL},
	}})
	a.RunPostStart(json.RawMessage(`{}`))

	time.Sleep(100 * time.Millisecond)
	if called {
		t.Fatal("webhook must not fire when disabled")
	}
}
