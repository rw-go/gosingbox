//go:build with_v2ray_api && with_clash_api

package controller

import (
	"bytes"
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime/debug"
	"strings"
	"testing"
	"time"

	"github.com/rwnode/rwnode-gosingbox/internal/app"
	"github.com/rwnode/rwnode-gosingbox/internal/contract"
	"github.com/rwnode/rwnode-gosingbox/internal/singbox"
	"github.com/rwnode/rwnode-gosingbox/internal/state"
	"github.com/rwnode/rwnode-gosingbox/internal/testutil"
	box "github.com/sagernet/sing-box"
	singtls "github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-shadowsocks/shadowaead_2022"
	singJSON "github.com/sagernet/sing/common/json"
	singlogger "github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	aTLS "github.com/sagernet/sing/common/tls"
)

func TestAnyTLSAuthorizationLifecycleThroughHandlers(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	ports := []int{testutil.Port(t), testutil.Port(t)}
	cfg := map[string]any{"log": map[string]any{"disabled": true}, "inbounds": []any{}, "outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}}}
	tlsOptions := testutil.TLS(t)
	for i, tag := range []string{"a", "b"} {
		cfg["inbounds"] = append(cfg["inbounds"].([]any), map[string]any{"type": "anytls", "tag": tag, "listen": "127.0.0.1", "listen_port": ports[i], "tls": tlsOptions, "users": []any{map[string]any{"name": "1", "password": testutil.UUID1}, map[string]any{"name": "2", "password": testutil.UUID2}}})
	}
	engine := singbox.NewEngine(singbox.Options{Logger: logger})
	if err := engine.ApplyConfig(cfg); err != nil {
		t.Fatal(err)
	}
	st := state.New()
	users, err := state.FromConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	st.Commit([]byte(`{"test":"prepared-native"}`), users, contract.SingBoxConfig)
	a := app.New(logger, engine, st, 5000, false)
	t.Cleanup(a.Stop)
	mux := http.NewServeMux()
	NewHandler(a, logger).Router(mux)
	call := func(path, body string, want bool) {
		t.Helper()
		r := httptest.NewRecorder()
		mux.ServeHTTP(r, httptest.NewRequest("POST", "/node/handler/"+path, strings.NewReader(body)))
		var result struct {
			Response struct {
				Success bool
				Error   string
			}
		}
		if err := json.Unmarshal(r.Body.Bytes(), &result); err != nil {
			t.Fatal(err)
		}
		if r.Code != 200 || result.Response.Success != want {
			t.Fatalf("%s: %s", path, r.Body.String())
		}
	}
	destination := testutil.Echo(t)
	oldA := testutil.NewClient(t, ports[0], testutil.UUID1)
	oldB := testutil.NewClient(t, ports[1], testutil.UUID1)
	other := testutil.NewClient(t, ports[0], testutil.UUID2)
	active, err := oldA.Open(destination)
	if err != nil {
		t.Fatal(err)
	}
	defer active.Close()
	if err = testutil.Ping(active); err != nil {
		t.Fatal(err)
	}
	for _, client := range []*testutil.Client{oldB, other} {
		if err := client.RoundTrip(destination); err != nil {
			t.Fatal(err)
		}
	}
	update := fmt.Sprintf(`{"hashData":{"vlessUuid":%q},"data":[{"type":"anytls","tag":"b","username":"1","password":%q}]}`, testutil.UUID1, testutil.UUID1)
	call("add-user", update, true)
	if err = testutil.Ping(active); err == nil {
		t.Fatal("revoked active stream still works")
	}
	if err = oldA.RoundTrip(destination); err == nil {
		t.Fatal("revoked session/new authentication accepted")
	}
	if err = oldB.RoundTrip(destination); err != nil || oldB.Dials.Load() != 1 {
		t.Fatalf("authorized session interrupted: %v dials=%d", err, oldB.Dials.Load())
	}
	if err = other.RoundTrip(destination); err != nil || other.Dials.Load() != 1 {
		t.Fatal("unaffected user interrupted")
	}
	// Idempotent retry must retain sessions.
	call("add-user", update, true)
	rotate := fmt.Sprintf(`{"affectedInboundTags":["a","b"],"users":[{"inboundData":[{"type":"anytls","tag":"b"}],"userData":{"userId":"1","hashUuid":%q,"vlessUuid":%q}}]}`, testutil.UUID3, testutil.UUID3)
	call("add-users", rotate, true)
	if err = oldB.RoundTrip(destination); err == nil {
		t.Fatal("old idle session/password survived rotation")
	}
	fresh := testutil.NewClient(t, ports[1], testutil.UUID3)
	if err = fresh.RoundTrip(destination); err != nil {
		t.Fatal(err)
	}
	// Bad second entry must not apply the otherwise valid first removal.
	before, _ := st.Snapshot()
	call("add-users", `{"users":[{"userData":{"userId":"2"},"inboundData":[]},{"userData":{"userId":"1"},"inboundData":[{"type":"anytls","tag":"missing"}]}]}`, false)
	after, _ := st.Snapshot()
	if len(after["a"].Users) != len(before["a"].Users) {
		t.Fatal("partial batch applied")
	}
	if err = other.RoundTrip(destination); err != nil {
		t.Fatal(err)
	}
	call("remove-user", fmt.Sprintf(`{"username":"1","hashData":{"vlessUuid":%q}}`, testutil.UUID3), true)
	if err = fresh.RoundTrip(destination); err == nil {
		t.Fatal("idle session survived removal")
	}
	call("remove-user", fmt.Sprintf(`{"username":"1","hashData":{"vlessUuid":%q}}`, testutil.UUID3), true)
	if err = other.RoundTrip(destination); err != nil || other.Dials.Load() != 1 {
		t.Fatal("unrelated session lost")
	}
}

func startLoopbackRealityTarget(t *testing.T) string {
	t.Helper()
	tlsMap := testutil.TLS(t)
	cert, err := tls.X509KeyPair(
		[]byte(strings.Join(tlsMap["certificate"].([]string), "\n")),
		[]byte(strings.Join(tlsMap["key"].([]string), "\n")),
	)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = ln.Close() })
	go func() {
		for {
			c, acceptErr := ln.Accept()
			if acceptErr != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(io.Discard, c) }()
		}
	}()
	return ln.Addr().String()
}

func startLoopbackSocksOutbound(t *testing.T, outbound map[string]any) int {
	t.Helper()
	socksPort := testutil.Port(t)
	cfg := map[string]any{
		"log":       map[string]any{"disabled": true},
		"inbounds":  []any{map[string]any{"type": "socks", "tag": "socks-in", "listen": "127.0.0.1", "listen_port": socksPort}},
		"outbounds": []any{outbound},
		"route":     map[string]any{"final": outbound["tag"]},
	}
	data, err := json.Marshal(cfg)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(include.Context(context.Background()))
	opts, err := singJSON.UnmarshalExtendedContext[option.Options](ctx, data)
	if err != nil {
		cancel()
		t.Fatalf("parse client options: %v", err)
	}
	inst, err := box.New(box.Options{Context: ctx, Options: opts})
	if err != nil {
		cancel()
		t.Fatalf("create client box: %v", err)
	}
	if err := inst.Start(); err != nil {
		inst.Close()
		cancel()
		t.Fatalf("start client box: %v", err)
	}
	t.Cleanup(func() { _ = inst.Close(); cancel() })
	return socksPort
}

func socks5Ping(socksPort int, dest string) error {
	host, portStr, err := net.SplitHostPort(dest)
	if err != nil {
		return err
	}
	var port int
	_, _ = fmt.Sscanf(portStr, "%d", &port)
	ip := net.ParseIP(host).To4()
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), 2*time.Second)
	if err != nil {
		return err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		return err
	}
	greet := make([]byte, 2)
	if _, err := io.ReadFull(conn, greet); err != nil {
		return err
	}
	req := []byte{0x05, 0x01, 0x00, 0x01, ip[0], ip[1], ip[2], ip[3], byte(port >> 8), byte(port)}
	if _, err := conn.Write(req); err != nil {
		return err
	}
	rep := make([]byte, 10)
	if _, err := io.ReadFull(conn, rep); err != nil || rep[1] != 0x00 {
		return fmt.Errorf("socks connect rejected: err=%v rep=%v", err, rep)
	}
	return testutil.Ping(conn)
}

func openSS2022Conn(port int, password, dest string) (net.Conn, error) {
	method, err := shadowaead_2022.NewWithPassword("2022-blake3-aes-256-gcm", password, nil)
	if err != nil {
		return nil, err
	}
	raw, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		return nil, err
	}
	_ = raw.SetDeadline(time.Now().Add(2 * time.Second))
	conn, err := method.DialConn(raw, M.ParseSocksaddr(dest))
	if err != nil {
		_ = raw.Close()
		return nil, err
	}
	return conn, nil
}

func pingSS2022(port int, password, dest string) error {
	conn, err := openSS2022Conn(port, password, dest)
	if err != nil {
		return err
	}
	defer conn.Close()
	return testutil.Ping(conn)
}

func startUDPEcho(t *testing.T) net.Addr {
	t.Helper()
	udp, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = udp.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, rErr := udp.ReadFrom(buf)
			if rErr != nil {
				return
			}
			_, _ = udp.WriteTo(buf[:n], addr)
		}
	}()
	return udp.LocalAddr()
}

func TestJP4XrayVLESSRealityAndSS2022RelayLifecycleThroughEndpoints(t *testing.T) {
	h := newNativeHarness(t)

	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	realityPriv := base64.RawURLEncoding.EncodeToString(privKey.Bytes())
	realityPub := base64.RawURLEncoding.EncodeToString(privKey.PublicKey().Bytes())
	realityTarget := startLoopbackRealityTarget(t)
	echoDest := testutil.Echo(t)

	ssPort := testutil.Port(t)
	vlessPort := testutil.Port(t)
	serverPSK := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x42}, 32))
	rawUser1SS := "abcdefghijklmnopqrstuvwxyz123456"
	user1SSKey := base64.StdEncoding.EncodeToString([]byte(rawUser1SS))
	user2SSKey := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x77}, 32))

	makeJP4Xray := func(ssClients []any) map[string]any {
		return map[string]any{
			"log": map[string]any{"loglevel": "none"},
			"routing": map[string]any{
				"rules": []any{
					map[string]any{"protocol": []any{"bittorrent"}, "outboundTag": "BLOCK"},
				},
			},
			"inbounds": []any{
				map[string]any{
					"tag":      "SS_IN_JP4",
					"listen":   "127.0.0.1",
					"port":     ssPort,
					"protocol": "shadowsocks",
					"settings": map[string]any{
						"method":   "2022-blake3-aes-256-gcm",
						"clients":  ssClients,
						"network":  "tcp,udp",
						"password": serverPSK,
					},
					"sniffing": map[string]any{"enabled": true, "destOverride": []any{"http", "tls", "quic"}},
				},
				map[string]any{
					"tag":      "VLESS_PUBLIC_INBOUND_JP4",
					"listen":   "127.0.0.1",
					"port":     vlessPort,
					"protocol": "vless",
					"settings": map[string]any{
						"clients": []any{
							map[string]any{"id": testutil.UUID1, "email": "1", "flow": "xtls-rprx-vision"},
						},
						"decryption": "none",
					},
					"sniffing": map[string]any{"enabled": true, "destOverride": []any{"http", "tls", "quic"}},
					"streamSettings": map[string]any{
						"network":  "raw",
						"security": "reality",
						"realitySettings": map[string]any{
							"target":       realityTarget,
							"shortIds":     []any{"010203040506"},
							"privateKey":   realityPriv,
							"serverNames":  []any{"next.tama.ac.jp"},
							"maxClientVer": "",
							"minClientVer": "1.8.2",
						},
					},
				},
			},
			"outbounds": []any{
				map[string]any{"tag": "DIRECT", "protocol": "freedom"},
				map[string]any{"tag": "BLOCK", "protocol": "blackhole"},
			},
		}
	}

	callHandler := func(path string, body any, wantSuccess bool) {
		t.Helper()
		rec := h.call("POST", "/node/handler/"+path, body)
		var res struct {
			Response struct {
				Success bool
				Error   string
			}
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
			t.Fatal(err)
		}
		if rec.Code != 200 || res.Response.Success != wantSuccess {
			t.Fatalf("%s status=%d want=%v body=%s", path, rec.Code, wantSuccess, rec.Body.String())
		}
	}

	checkVLESS := func(socksPort int, userID, wantUUID string) error {
		snap, _ := h.state.Snapshot()
		u, ok := snap["VLESS_PUBLIC_INBOUND_JP4"].Users[userID]
		if !ok || u.Credential != wantUUID || u.Flow != "xtls-rprx-vision" {
			return fmt.Errorf("VLESS state mismatch for user %q: %+v (ok=%v)", userID, u, ok)
		}
		// Upstream github.com/sagernet/sing-vmess/vless/vision.go:89 converts a
		// uintptr back to unsafe.Pointer, triggering Go's -d=checkptr abort when
		// compiled with -race. Under -race we verify the live Reality+uTLS
		// handshake on VLESS_PUBLIC_INBOUND_JP4; non-race runs exercise the full
		// xtls-rprx-vision TCP echo round-trip.
		if info, ok := debug.ReadBuildInfo(); ok {
			for _, s := range info.Settings {
				if s.Key == "-race" && s.Value == "true" {
					ctx, cancel := context.WithTimeout(include.Context(context.Background()), 2*time.Second)
					defer cancel()
					tlsCfg, cfgErr := singtls.NewClientWithOptions(singtls.ClientOptions{
						Context:       ctx,
						Logger:        singlogger.NOP(),
						ServerAddress: "127.0.0.1",
						Options: option.OutboundTLSOptions{
							Enabled:    true,
							ServerName: "next.tama.ac.jp",
							UTLS:       &option.OutboundUTLSOptions{Enabled: true, Fingerprint: "chrome"},
							Reality:    &option.OutboundRealityOptions{Enabled: true, PublicKey: realityPub, ShortID: "010203040506"},
						},
					})
					if cfgErr != nil {
						return cfgErr
					}
					rawConn, dialErr := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", vlessPort), 2*time.Second)
					if dialErr != nil {
						return dialErr
					}
					defer rawConn.Close()
					tlsConn, hsErr := aTLS.ClientHandshake(ctx, rawConn, tlsCfg)
					if hsErr != nil {
						return hsErr
					}
					return tlsConn.Close()
				}
			}
		}
		return socks5Ping(socksPort, echoDest)
	}

	// 1. Start jp4-shaped Xray config (VLESS 1 user + SS2022 clients=[] 0 users).
	udpDest := startUDPEcho(t)
	h.start(makeJP4Xray([]any{}), "", false, "")

	vlessUser1Socks := startLoopbackSocksOutbound(t, map[string]any{
		"type": "vless", "tag": "vl-u1", "server": "127.0.0.1", "server_port": vlessPort,
		"uuid": testutil.UUID1, "flow": "xtls-rprx-vision",
		"tls": map[string]any{
			"enabled": true, "server_name": "next.tama.ac.jp",
			"utls":    map[string]any{"enabled": true, "fingerprint": "chrome"},
			"reality": map[string]any{"enabled": true, "public_key": realityPub, "short_id": "010203040506"},
		},
	})
	jp1sbRelaySocks := startLoopbackSocksOutbound(t, map[string]any{
		"type": "shadowsocks", "tag": "ss_to_jp4", "method": "2022-blake3-aes-256-gcm",
		"server": "127.0.0.1", "server_port": ssPort, "password": serverPSK,
	})

	// Verify 0-user Xray SS2022 TCP & UDP single-password PSK FIRST and confirm 0 personal user traffic charged.
	if err := socks5Ping(jp1sbRelaySocks, echoDest); err != nil {
		t.Fatalf("jp1sb -> SS_IN_JP4 single-password TCP relay traffic failed: %v", err)
	}
	if err := fixedSSPacketPing(ssPort, serverPSK, udpDest); err != nil {
		t.Fatalf("SS_IN_JP4 single-password UDP relay traffic failed: %v", err)
	}
	userCounters, err := h.app.QueryUserCounters(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range userCounters {
		if c.Value != 0 {
			t.Fatalf("0-user Xray SS2022 PSK relay charged personal user traffic: %+v", c)
		}
	}
	if err := checkVLESS(vlessUser1Socks, "1", testutil.UUID1); err != nil {
		t.Fatalf("VLESS_PUBLIC_INBOUND_JP4 traffic failed: %v", err)
	}

	// Verify /node/stats/get-inbound-stats tracks SS_IN_JP4 node traffic.
	statRec := h.call("POST", "/node/stats/get-inbound-stats", map[string]any{"tag": "SS_IN_JP4", "reset": false})
	var ibStat struct {
		Response struct {
			Inbound  string `json:"inbound"`
			Uplink   int64  `json:"uplink"`
			Downlink int64  `json:"downlink"`
		} `json:"response"`
	}
	if err := json.Unmarshal(statRec.Body.Bytes(), &ibStat); err != nil {
		t.Fatal(err)
	}
	if ibStat.Response.Inbound != "SS_IN_JP4" || ibStat.Response.Uplink < 4 || ibStat.Response.Downlink < 4 {
		t.Fatalf("expected SS_IN_JP4 inbound stats > 0, got %s", statRec.Body.String())
	}

	// 2. Unrelated VLESS hot user add/remove via /node/handler/add-user & remove-user
	// must NOT restart listeners or break an active single-password SS2022 stream.
	openRelay, err := openSS2022Conn(ssPort, serverPSK, echoDest)
	if err != nil {
		t.Fatalf("open SS_IN_JP4 stream failed: %v", err)
	}
	defer openRelay.Close()
	if err := testutil.Ping(openRelay); err != nil {
		t.Fatal(err)
	}

	callHandler("add-user", map[string]any{
		"hashData": map[string]any{"vlessUuid": testutil.UUID2},
		"data": []any{map[string]any{
			"type": "vless", "tag": "VLESS_PUBLIC_INBOUND_JP4", "username": "2", "uuid": testutil.UUID2, "flow": "xtls-rprx-vision",
		}},
	}, true)
	vlessUser2Socks := startLoopbackSocksOutbound(t, map[string]any{
		"type": "vless", "tag": "vl-u2", "server": "127.0.0.1", "server_port": vlessPort,
		"uuid": testutil.UUID2, "flow": "xtls-rprx-vision",
		"tls": map[string]any{
			"enabled": true, "server_name": "next.tama.ac.jp",
			"utls":    map[string]any{"enabled": true, "fingerprint": "chrome"},
			"reality": map[string]any{"enabled": true, "public_key": realityPub, "short_id": "010203040506"},
		},
	})
	if err := checkVLESS(vlessUser2Socks, "2", testutil.UUID2); err != nil {
		t.Fatalf("hot-added VLESS user 2 failed: %v", err)
	}
	if err := testutil.Ping(openRelay); err != nil {
		t.Fatalf("VLESS add-user interrupted active SS_IN_JP4 stream: %v", err)
	}

	callHandler("remove-user", map[string]any{
		"username": "2",
		"hashData": map[string]any{"vlessUuid": testutil.UUID2},
	}, true)
	if err := testutil.Ping(openRelay); err != nil {
		t.Fatalf("VLESS remove-user interrupted active SS_IN_JP4 stream: %v", err)
	}

	// 3a. 0 -> >0 SS2022 promotion via incremental /node/handler/add-user & /node/handler/add-users:
	// First verify an invalid short key fails prevalidation without breaking openRelay.
	callHandler("add-user", map[string]any{
		"hashData": map[string]any{"vlessUuid": testutil.UUID2},
		"data": []any{map[string]any{
			"type": "shadowsocks22", "tag": "SS_IN_JP4", "username": "2", "password": base64.StdEncoding.EncodeToString([]byte("too-short")),
		}},
	}, false)
	if err := testutil.Ping(openRelay); err != nil {
		t.Fatalf("rejected SS2022 promotion interrupted active SS_IN_JP4 stream: %v", err)
	}
	_ = openRelay.Close()

	// Promote via /node/handler/add-users (batch endpoint base64-encodes ssPassword).
	callHandler("add-users", map[string]any{
		"affectedInboundTags": []string{"VLESS_PUBLIC_INBOUND_JP4", "SS_IN_JP4"},
		"users": []any{map[string]any{
			"userData": map[string]any{
				"userId":     "1",
				"hashUuid":   testutil.UUID1,
				"vlessUuid":  testutil.UUID1,
				"ssPassword": rawUser1SS,
			},
			"inboundData": []any{
				map[string]any{"type": "vless", "tag": "VLESS_PUBLIC_INBOUND_JP4", "flow": "xtls-rprx-vision"},
				map[string]any{"type": "shadowsocks22", "tag": "SS_IN_JP4"},
			},
		}},
	}, true)
	if err := pingSS2022(ssPort, serverPSK+":"+user1SSKey, echoDest); err != nil {
		t.Fatalf("EIH failed after incremental 0->1 add-users promotion: %v", err)
	}
	if err := pingSS2022(ssPort, serverPSK, echoDest); err == nil {
		t.Fatal("bare server PSK accepted after incremental promotion to MultiInbound")
	}
	if err := checkVLESS(vlessUser1Socks, "1", testutil.UUID1); err != nil {
		t.Fatalf("VLESS user 1 failed after SS_IN_JP4 promotion: %v", err)
	}

	// Restore 0-user single-password PSK via full /node/xray/start (forceRestart: false, clients: []),
	// then also verify 0 -> >0 via single /node/handler/add-user.
	h.start(makeJP4Xray([]any{}), "", false, "")
	if err := pingSS2022(ssPort, serverPSK, echoDest); err != nil {
		t.Fatalf("single-user PSK not restored by full start with clients=[]: %v", err)
	}
	callHandler("add-user", map[string]any{
		"hashData": map[string]any{"vlessUuid": testutil.UUID2},
		"data": []any{map[string]any{
			"type": "shadowsocks22", "tag": "SS_IN_JP4", "username": "2", "password": user2SSKey,
		}},
	}, true)
	if err := pingSS2022(ssPort, serverPSK+":"+user2SSKey, echoDest); err != nil {
		t.Fatalf("EIH failed after single add-user 0->1 promotion: %v", err)
	}
	if err := pingSS2022(ssPort, serverPSK, echoDest); err == nil {
		t.Fatal("bare server PSK accepted after single add-user promotion")
	}

	// Reset back to 0-user single-password PSK, then test 3b: 0 -> >0 via full /node/xray/start (forceRestart: false).
	h.start(makeJP4Xray([]any{}), "", false, "")
	if err := pingSS2022(ssPort, serverPSK, echoDest); err != nil {
		t.Fatalf("single-user PSK failed before 3b: %v", err)
	}
	h.start(makeJP4Xray([]any{map[string]any{"email": "1", "password": user1SSKey, "id": testutil.UUID1}}), "", false, "")
	if err := pingSS2022(ssPort, serverPSK+":"+user1SSKey, echoDest); err != nil {
		t.Fatalf("EIH failed after full /node/xray/start 0->1 promotion: %v", err)
	}
	if err := pingSS2022(ssPort, serverPSK, echoDest); err == nil {
		t.Fatal("bare server PSK accepted after full /node/xray/start 0->1 promotion")
	}

	// 4. >0 -> 0 SS2022 users (even when initial start at line 544 had 1 user in raw clients!):
	// incremental remove-users revokes EIH immediately (closing active EIH streams) AND restores
	// single-user PSK relay mode; full /node/xray/start with clients=[] also restores PSK mode.
	activeEIH, err := openSS2022Conn(ssPort, serverPSK+":"+user1SSKey, echoDest)
	if err != nil {
		t.Fatalf("open active EIH stream failed: %v", err)
	}
	defer activeEIH.Close()
	if err := testutil.Ping(activeEIH); err != nil {
		t.Fatal(err)
	}

	callHandler("remove-users", map[string]any{
		"users": []any{map[string]any{"userId": "1", "hashUuid": testutil.UUID1}},
	}, true)
	if err := testutil.Ping(activeEIH); err == nil {
		t.Fatal("active EIH stream survived >0 -> 0 remove-users")
	}
	if err := pingSS2022(ssPort, serverPSK+":"+user1SSKey, echoDest); err == nil {
		t.Fatal("revoked EIH user accepted after incremental remove-users")
	}
	if err := socks5Ping(jp1sbRelaySocks, echoDest); err != nil {
		t.Fatalf("incremental >0 -> 0 remove-users (from 1-user raw) did not restore single-user TCP PSK: %v", err)
	}
	if err := fixedSSPacketPing(ssPort, serverPSK, udpDest); err != nil {
		t.Fatalf("incremental >0 -> 0 remove-users (from 1-user raw) did not restore single-user UDP PSK: %v", err)
	}

	// Re-promote via full start with 1 user, then demote >0 -> 0 via full /node/xray/start with clients=[].
	h.start(makeJP4Xray([]any{map[string]any{"email": "1", "password": user1SSKey, "id": testutil.UUID1}}), "", false, "")
	if err := pingSS2022(ssPort, serverPSK+":"+user1SSKey, echoDest); err != nil {
		t.Fatal(err)
	}
	h.start(makeJP4Xray([]any{}), "", false, "")
	if err := pingSS2022(ssPort, serverPSK+":"+user1SSKey, echoDest); err == nil {
		t.Fatal("EIH accepted after full /node/xray/start >0 -> 0 demotion")
	}
	if err := socks5Ping(jp1sbRelaySocks, echoDest); err != nil {
		t.Fatalf("full /node/xray/start with clients=[] did not restore jp1sb->SS_IN_JP4 PSK relay: %v", err)
	}
	if err := checkVLESS(vlessUser1Socks, "1", testutil.UUID1); err != nil {
		t.Fatalf("VLESS failed after restoring single-user SS_IN_JP4 relay: %v", err)
	}
}

func TestNativeSS2022UnifiedPasswordRuleThroughEndpoints(t *testing.T) {
	h := newNativeHarness(t)
	echoDest := testutil.Echo(t)
	udpDest := startUDPEcho(t)

	ssOmittedPort := testutil.Port(t)
	ssEmptyPort := testutil.Port(t)
	ssManagedPort := testutil.Port(t)
	pskOmitted := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x11}, 32))
	pskEmpty := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x22}, 32))
	pskManaged := base64.StdEncoding.EncodeToString(bytes.Repeat([]byte{0x33}, 32))
	rawUser1SS := "0123456789abcdef0123456789abcdef"
	user1SSKey := base64.StdEncoding.EncodeToString([]byte(rawUser1SS))

	makeNativeCfg := func(managedUsers []any, includeManagedFlag bool) map[string]any {
		hk1sbInbound := map[string]any{
			"type": "shadowsocks", "tag": "SS_HK1SB",
			"listen": "127.0.0.1", "listen_port": ssManagedPort,
			"method": "2022-blake3-aes-256-gcm", "password": pskManaged,
			"users": managedUsers,
		}
		if includeManagedFlag {
			hk1sbInbound["managed"] = true
		}
		return map[string]any{
			"log": map[string]any{"disabled": true},
			"inbounds": []any{
				map[string]any{
					"type": "anytls", "tag": "any", "listen": "127.0.0.1", "listen_port": h.port,
					"tls":   testutil.TLS(t),
					"users": []any{map[string]any{"name": "1", "password": testutil.UUID1}},
				},
				map[string]any{
					"type": "shadowsocks", "tag": "SS_OMITTED",
					"listen": "127.0.0.1", "listen_port": ssOmittedPort,
					"method": "2022-blake3-aes-256-gcm", "password": pskOmitted,
				},
				map[string]any{
					"type": "shadowsocks", "tag": "SS_EMPTY",
					"listen": "127.0.0.1", "listen_port": ssEmptyPort,
					"method": "2022-blake3-aes-256-gcm", "password": pskEmpty,
					"users": []any{},
				},
				hk1sbInbound,
			},
			"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
			"route":     map[string]any{"final": "direct"},
		}
	}

	callHandler := func(path string, body any, wantSuccess bool) {
		t.Helper()
		rec := h.call("POST", "/node/handler/"+path, body)
		var res struct {
			Response struct {
				Success bool
				Error   string
			}
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
			t.Fatal(err)
		}
		if rec.Code != 200 || res.Response.Success != wantSuccess {
			t.Fatalf("%s status=%d want=%v body=%s", path, rec.Code, wantSuccess, rec.Body.String())
		}
	}

	assertTCPEcho := func(port int, secret string) {
		t.Helper()
		if err := pingSS2022(port, secret, echoDest); err != nil {
			t.Fatalf("TCP SS2022 failed on port %d: %v", port, err)
		}
	}
	assertUDPEcho := func(port int, secret string) {
		t.Helper()
		if err := fixedSSPacketPing(port, secret, udpDest); err != nil {
			t.Fatalf("UDP SS2022 failed on port %d: %v", port, err)
		}
	}

	// 1. Start Native with all 3 0-user SS2022 shapes: users omitted, users=[], and users=[]+managed=true (hk1sb).
	h.start(makeNativeCfg([]any{}, true), "singbox", false, "")
	for _, entry := range []struct {
		tag  string
		port int
		psk  string
	}{
		{"SS_OMITTED", ssOmittedPort, pskOmitted},
		{"SS_EMPTY", ssEmptyPort, pskEmpty},
		{"SS_HK1SB", ssManagedPort, pskManaged},
	} {
		assertTCPEcho(entry.port, entry.psk)
		assertUDPEcho(entry.port, entry.psk)
		statRec := h.call("POST", "/node/stats/get-inbound-stats", map[string]any{"tag": entry.tag, "reset": false})
		var ibStat struct {
			Response struct {
				Inbound  string `json:"inbound"`
				Uplink   int64  `json:"uplink"`
				Downlink int64  `json:"downlink"`
			} `json:"response"`
		}
		if err := json.Unmarshal(statRec.Body.Bytes(), &ibStat); err != nil {
			t.Fatal(err)
		}
		if ibStat.Response.Inbound != entry.tag || ibStat.Response.Uplink < 4 || ibStat.Response.Downlink < 4 {
			t.Fatalf("expected node inbound stats > 0 for %s, got %s", entry.tag, statRec.Body.String())
		}
	}
	userCounters, err := h.app.QueryUserCounters(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	for _, c := range userCounters {
		if c.Value != 0 {
			t.Fatalf("0-user Native SS2022 PSK relay charged personal user traffic: %+v", c)
		}
	}

	// 2a. Native 0 -> >0 via incremental /node/handler/add-users switches SS_HK1SB to EIH.
	callHandler("add-users", map[string]any{
		"affectedInboundTags": []string{"any", "SS_HK1SB"},
		"users": []any{map[string]any{
			"userData": map[string]any{
				"userId":     "1",
				"hashUuid":   testutil.UUID1,
				"vlessUuid":  testutil.UUID1,
				"ssPassword": rawUser1SS,
			},
			"inboundData": []any{
				map[string]any{"type": "anytls", "tag": "any"},
				map[string]any{"type": "shadowsocks22", "tag": "SS_HK1SB"},
			},
		}},
	}, true)
	assertTCPEcho(ssManagedPort, pskManaged+":"+user1SSKey)
	assertUDPEcho(ssManagedPort, pskManaged+":"+user1SSKey)
	if err := pingSS2022(ssManagedPort, pskManaged, echoDest); err == nil {
		t.Fatal("promoted Native SS_HK1SB accepted bare PSK")
	}
	assertTCPEcho(ssOmittedPort, pskOmitted)
	assertTCPEcho(ssEmptyPort, pskEmpty)

	// 2b. Native >0 -> 0 via full /node/xray/start (users=[], managed=true, forceRestart: false) restores PSK,
	// and Native 0 -> >0 via full /node/xray/start (1 user, forceRestart: false) switches to EIH.
	h.start(makeNativeCfg([]any{}, true), "singbox", false, "")
	assertTCPEcho(ssManagedPort, pskManaged)
	assertUDPEcho(ssManagedPort, pskManaged)

	h.start(makeNativeCfg([]any{map[string]any{"name": "1", "password": user1SSKey}}, false), "singbox", false, "")
	assertTCPEcho(ssManagedPort, pskManaged+":"+user1SSKey)
	if err := pingSS2022(ssManagedPort, pskManaged, echoDest); err == nil {
		t.Fatal("full-start Native EIH accepted bare PSK")
	}

	// 3. Native >0 -> 0 via incremental /node/handler/remove-users (when initial start had 1 user in raw!):
	// closes active EIH stream, rejects new EIH handshakes, immediately restores PSK, and cleans get-config.
	activeNativeEIH, err := openSS2022Conn(ssManagedPort, pskManaged+":"+user1SSKey, echoDest)
	if err != nil {
		t.Fatalf("open active Native EIH stream failed: %v", err)
	}
	defer activeNativeEIH.Close()
	if err := testutil.Ping(activeNativeEIH); err != nil {
		t.Fatal(err)
	}

	callHandler("remove-users", map[string]any{
		"users": []any{map[string]any{"userId": "1", "hashUuid": testutil.UUID1}},
	}, true)
	if err := testutil.Ping(activeNativeEIH); err == nil {
		t.Fatal("active Native EIH stream survived >0 -> 0 remove-users")
	}
	if err := pingSS2022(ssManagedPort, pskManaged+":"+user1SSKey, echoDest); err == nil {
		t.Fatal("revoked Native EIH user accepted after >0 -> 0 remove-users")
	}
	assertTCPEcho(ssManagedPort, pskManaged)
	assertUDPEcho(ssManagedPort, pskManaged)

	view := h.call("GET", "/internal/get-config", nil)
	if strings.Contains(view.Body.String(), user1SSKey) {
		t.Fatalf("GET /internal/get-config leaked stale SS2022 user key after 1->0 demotion: %s", view.Body.String())
	}
	var viewed map[string]any
	if err := json.Unmarshal(view.Body.Bytes(), &viewed); err != nil {
		t.Fatal(err)
	}
	for _, item := range viewed["inbounds"].([]any) {
		ib := item.(map[string]any)
		if ib["type"] != "shadowsocks" {
			continue
		}
		if _, hasManaged := ib["managed"]; hasManaged {
			t.Fatalf("GET /internal/get-config leaked managed flag on %v", ib["tag"])
		}
		switch ib["tag"] {
		case "SS_OMITTED":
			if _, hasUsers := ib["users"]; hasUsers {
				t.Fatalf("GET /internal/get-config added users to SS_OMITTED: %#v", ib["users"])
			}
		case "SS_EMPTY", "SS_HK1SB":
			uList, ok := ib["users"].([]any)
			if !ok || len(uList) != 0 {
				t.Fatalf("GET /internal/get-config did not clear users to [] on %v: %#v", ib["tag"], ib["users"])
			}
		}
	}
}
