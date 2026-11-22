//go:build with_v2ray_api && with_clash_api

package app

import (
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
	"runtime/debug"
	"strings"
	"sync"
	"testing"
	"time"

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

func TestXrayInputPerInboundHotUpdateAndEmptySSRecovery(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	stats := fmt.Sprintf("127.0.0.1:%d", testutil.Port(t))
	clash := fmt.Sprintf("127.0.0.1:%d", testutil.Port(t))
	engine := singbox.NewEngine(singbox.Options{StatsAddr: stats, ClashAddr: clash, Logger: logger})
	st := state.New()
	a := New(logger, engine, st, 5000, false)
	defer a.Stop()
	p1, p2 := testutil.Port(t), testutil.Port(t)
	key := base64.StdEncoding.EncodeToString([]byte("12345678901234567890123456789012"))
	user1 := base64.StdEncoding.EncodeToString([]byte("abcdefghijklmnopqrstuvwxyz123456"))
	user2 := base64.StdEncoding.EncodeToString([]byte("123456abcdefghijklmnopqrstuvwxyz"))
	user3 := base64.StdEncoding.EncodeToString([]byte("00000011111122222233333344444455"))
	panel := map[string]any{"inbounds": []any{}}
	inbound := func(tag string, port int, clients []any) map[string]any {
		return map[string]any{"protocol": "shadowsocks", "tag": tag, "listen": "127.0.0.1", "port": port, "settings": map[string]any{"method": "2022-blake3-aes-256-gcm", "password": key, "clients": clients}}
	}
	panel["inbounds"] = []any{
		inbound("a", p1, []any{map[string]any{"email": "1", "password": user1}, map[string]any{"email": "3", "password": user3}}),
		inbound("b", p2, []any{map[string]any{"email": "2", "password": user2}}),
	}
	raw, err := json.Marshal(panel)
	if err != nil {
		t.Fatal(err)
	}
	if err = a.StartWithForce(raw, false); err != nil {
		t.Fatal(err)
	}
	snapshot, _ := st.Snapshot()
	if len(snapshot["a"].Users) != 2 || snapshot["a"].Users["1"].Credential != user1 || snapshot["a"].Users["3"].Credential != user3 || snapshot["b"].Users["2"].Credential != user2 {
		t.Fatal("initial users leaked between inbounds")
	}
	dest := testutil.Echo(t)
	single, err := shadowaead_2022.NewWithPassword("2022-blake3-aes-256-gcm", key, nil)
	if err != nil {
		t.Fatal(err)
	}
	open := func(port int, credential string) (net.Conn, error) {
		r, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		if err != nil {
			return nil, err
		}
		client, err := shadowaead_2022.NewWithPassword("2022-blake3-aes-256-gcm", key+":"+credential, nil)
		if err != nil {
			r.Close()
			return nil, err
		}
		_ = r.SetDeadline(time.Now().Add(500 * time.Millisecond))
		conn, err := client.DialConn(r, M.ParseSocksaddr(dest))
		if err != nil {
			r.Close()
		}
		return conn, err
	}
	pingBarePSK := func(port int) error {
		r, dialErr := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), time.Second)
		if dialErr != nil {
			return dialErr
		}
		defer r.Close()
		_ = r.SetDeadline(time.Now().Add(time.Second))
		c, hsErr := single.DialConn(r, M.ParseSocksaddr(dest))
		if hsErr != nil {
			return hsErr
		}
		defer c.Close()
		return testutil.Ping(c)
	}

	active, err := open(p2, user2)
	if err != nil {
		t.Fatal(err)
	}
	defer active.Close()
	if err = testutil.Ping(active); err != nil {
		t.Fatal(err)
	}
	// >0 -> >0 hot update (2 -> 1 users on "a") keeps MultiInbound without restarting listeners.
	if err = a.UpdateUsers([]state.Update{{ID: "1"}}); err != nil {
		t.Fatal(err)
	}
	if err = testutil.Ping(active); err != nil {
		t.Fatal("unaffected SS stream interrupted on >0 -> >0 hot update")
	}
	// An identical saved full push restores its users in-place without restarting listeners.
	if err = a.StartWithForce(raw, false); err != nil {
		t.Fatal(err)
	}
	snapshot, _ = st.Snapshot()
	if len(snapshot["a"].Users) != 2 {
		t.Fatal("identical full push ignored current user differences")
	}
	if err = testutil.Ping(active); err != nil {
		t.Fatal("full user-only push restarted listeners")
	}
	// Concurrent retries are serialized; unrelated users remain present.
	var wg sync.WaitGroup
	errors := make(chan error, 10)
	for i := 0; i < 10; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errors <- a.UpdateUsers([]state.Update{{ID: "1", Memberships: []state.Membership{{Tag: "a", Protocol: "shadowsocks22", User: state.User{ID: "1", Credential: user1}}}}})
		}()
	}
	wg.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	// Rollback while "a" still has >0 users keeps MultiInbound EIH and rejects bare PSK.
	if err = a.UpdateUsers([]state.Update{{ID: "1"}}); err != nil {
		t.Fatal(err)
	}
	invalid := map[string]any{"inbounds": []any{map[string]any{"type": "anytls", "tag": "bad", "listen": "127.0.0.1", "listen_port": 0}}}
	if err = engine.ApplyConfig(invalid); err == nil || !strings.Contains(err.Error(), "rolled back") {
		t.Fatalf("expected actual instance rollback: %v", err)
	}
	if !engine.IsRunning() {
		t.Fatal("failed apply did not restore previous core")
	}
	if pingBarePSK(p1) == nil {
		t.Fatal("non-empty MultiInbound accepted bare PSK after rollback")
	}
	_ = active.Close()

	// Incremental >0 -> 0 demotion on "a" (even though initial raw had 2 users in clients!)
	// must revoke EIH and immediately restore single-user PSK relay mode on "a".
	if err = a.UpdateUsers([]state.Update{{ID: "3"}}); err != nil {
		t.Fatal(err)
	}
	snapshot, _ = st.Snapshot()
	if _, managed := snapshot["a"]; managed || len(snapshot["b"].Users) != 1 {
		t.Fatalf("expected demoted inbound 'a' out of snapshot and 'b' retained, got %#v", snapshot)
	}
	if c, dialErr := open(p1, user3); dialErr == nil {
		err = testutil.Ping(c)
		_ = c.Close()
		if err == nil {
			t.Fatal("revoked EIH user 3 still accepted after >0 -> 0 demotion")
		}
	}
	if err = pingBarePSK(p1); err != nil {
		t.Fatalf("incremental >0 -> 0 demotion from non-empty raw did not restore single-user PSK: %v", err)
	}

	// Rebuild with an empty clients list via the public full configuration path:
	// inbound "a" runs in single-user PSK mode, and incremental UpdateUsers
	// promotes it cleanly to MultiInbound EIH while rejecting invalid keys first.
	panel["inbounds"].([]any)[0].(map[string]any)["settings"].(map[string]any)["clients"] = []any{}
	emptyConfig, _ := json.Marshal(panel)
	if err = a.StartWithForce(emptyConfig, true); err != nil {
		t.Fatal(err)
	}
	pskConn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", p1), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	pskClient, err := single.DialConn(pskConn, M.ParseSocksaddr(dest))
	if err != nil {
		_ = pskConn.Close()
		t.Fatalf("0-client Xray SS inbound did not accept single-password PSK: %v", err)
	}
	if err = testutil.Ping(pskClient); err != nil {
		_ = pskClient.Close()
		t.Fatalf("0-client Xray SS single-password PSK ping failed: %v", err)
	}
	// Invalid SS2022 user key on 0 -> >0 promotion must fail prevalidation without
	// restarting listeners or interrupting the active single-password PSK stream.
	if err = a.UpdateUsers([]state.Update{{ID: "1", Memberships: []state.Membership{{Tag: "a", Protocol: "shadowsocks22", User: state.User{ID: "1", Credential: base64.StdEncoding.EncodeToString([]byte("short-key"))}}}}}); err == nil {
		_ = pskClient.Close()
		t.Fatal("expected invalid SS2022 user key to fail prevalidation")
	}
	if err = testutil.Ping(pskClient); err != nil {
		_ = pskClient.Close()
		t.Fatalf("failed prevalidation interrupted active single-password SS stream: %v", err)
	}
	_ = pskClient.Close()

	if err = a.UpdateUsers([]state.Update{{ID: "1", Memberships: []state.Membership{{Tag: "a", Protocol: "shadowsocks22", User: state.User{ID: "1", Credential: user1}}}}}); err != nil {
		t.Fatal("empty SS inbound not updatable", err)
	}
	restored, err := open(p1, user1)
	if err != nil {
		t.Fatal(err)
	}
	defer restored.Close()
	if err = testutil.Ping(restored); err != nil {
		t.Fatal(err)
	}
	if pingBarePSK(p1) == nil {
		t.Fatal("promoted MultiInbound accepted bare server PSK")
	}

	// Incremental 1 -> 0 removal revokes EIH AND immediately restores single-user PSK relay mode.
	if err = a.UpdateUsers([]state.Update{{ID: "1"}}); err != nil {
		t.Fatal(err)
	}
	if c, dialErr := open(p1, user1); dialErr == nil {
		err = testutil.Ping(c)
		_ = c.Close()
		if err == nil {
			t.Fatal("revoked EIH user still accepted after 1->0 removal")
		}
	}
	if err = pingBarePSK(p1); err != nil {
		t.Fatalf("incremental 1->0 removal did not restore single-user PSK: %v", err)
	}

	// Promote 0 -> 1 via full StartWithForce(raw, false), then demote 1 -> 0 via StartWithForce(emptyConfig, false).
	if err = a.StartWithForce(raw, false); err != nil {
		t.Fatal(err)
	}
	if c, dialErr := open(p1, user1); dialErr != nil {
		t.Fatalf("full 0->2 start EIH failed: %v", dialErr)
	} else {
		_ = testutil.Ping(c)
		_ = c.Close()
	}
	if pingBarePSK(p1) == nil {
		t.Fatal("full >0 start accepted bare server PSK")
	}
	if err = a.StartWithForce(emptyConfig, false); err != nil {
		t.Fatal(err)
	}
	if err = pingBarePSK(p1); err != nil {
		t.Fatalf("subsequent full start with clients=[] did not restore single-user PSK: %v", err)
	}
}

func TestNativeSS2022ZeroAndMultiUserTransitions(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	stats := fmt.Sprintf("127.0.0.1:%d", testutil.Port(t))
	clash := fmt.Sprintf("127.0.0.1:%d", testutil.Port(t))
	engine := singbox.NewEngine(singbox.Options{StatsAddr: stats, ClashAddr: clash, Logger: logger})
	st := state.New()
	a := New(logger, engine, st, 0, false)
	defer a.Stop()

	ssPort := testutil.Port(t)
	serverPSK := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	userKey := base64.StdEncoding.EncodeToString([]byte("fedcba9876543210fedcba9876543210"))
	echoDest := testutil.Echo(t)

	ping := func(secret string) error {
		m, err := shadowaead_2022.NewWithPassword("2022-blake3-aes-256-gcm", secret, nil)
		if err != nil {
			return err
		}
		r, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", ssPort), time.Second)
		if err != nil {
			return err
		}
		defer r.Close()
		_ = r.SetDeadline(time.Now().Add(time.Second))
		c, err := m.DialConn(r, M.ParseSocksaddr(echoDest))
		if err != nil {
			return err
		}
		defer c.Close()
		return testutil.Ping(c)
	}

	makeNative := func(users any, withManaged bool) []byte {
		ib := map[string]any{
			"type": "shadowsocks", "tag": "ss-hk1sb",
			"listen": "127.0.0.1", "listen_port": ssPort,
			"method": "2022-blake3-aes-256-gcm", "password": serverPSK,
		}
		if users != nil {
			ib["users"] = users
		}
		if withManaged {
			ib["managed"] = true
		}
		raw, err := json.Marshal(map[string]any{
			"log":       map[string]any{"disabled": true},
			"inbounds":  []any{ib},
			"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
		})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}

	// 1. Start with hk1sb-style 0-user native SS2022 (users: [], managed: true, SS-only config!).
	if err := a.StartConfig(makeNative([]any{}, true), contract.SingBoxConfig, false); err != nil {
		t.Fatalf("0-user SS-only native StartConfig failed: %v", err)
	}
	if err := ping(serverPSK); err != nil {
		t.Fatalf("0-user native SS2022 PSK failed: %v", err)
	}

	// 2. Promote 0 -> 1 via UpdateUsers (rejecting short key first without breaking PSK).
	if err := a.UpdateUsers([]state.Update{{ID: "u1", Memberships: []state.Membership{{Tag: "ss-hk1sb", Protocol: "shadowsocks22", User: state.User{ID: "u1", Credential: base64.StdEncoding.EncodeToString([]byte("short"))}}}}}); err == nil {
		t.Fatal("expected short SS2022 key to fail prevalidation on native promotion")
	}
	if err := ping(serverPSK); err != nil {
		t.Fatalf("rejected native promotion broke PSK: %v", err)
	}
	if err := a.UpdateUsers([]state.Update{{ID: "u1", Memberships: []state.Membership{{Tag: "ss-hk1sb", Protocol: "shadowsocks22", User: state.User{ID: "u1", Credential: userKey}}}}}); err != nil {
		t.Fatalf("native 0->1 UpdateUsers promotion failed: %v", err)
	}
	if err := ping(serverPSK + ":" + userKey); err != nil {
		t.Fatalf("native EIH failed after 0->1 promotion: %v", err)
	}
	if err := ping(serverPSK); err == nil {
		t.Fatal("native MultiInbound accepted bare PSK after promotion")
	}

	// 3. Start with 1 user in raw, then demote 1 -> 0 via UpdateUsers and verify ConfigView is clean.
	if err := a.StartConfig(makeNative([]any{map[string]any{"name": "u1", "password": userKey}}, false), contract.SingBoxConfig, false); err != nil {
		t.Fatal(err)
	}
	if err := a.UpdateUsers([]state.Update{{ID: "u1"}}); err != nil {
		t.Fatalf("native 1->0 UpdateUsers demotion failed: %v", err)
	}
	if err := ping(serverPSK + ":" + userKey); err == nil {
		t.Fatal("revoked native EIH user still accepted after 1->0 demotion")
	}
	if err := ping(serverPSK); err != nil {
		t.Fatalf("native 1->0 demotion did not restore single-user PSK: %v", err)
	}
	_, view := a.ConfigView()
	ibView := view["inbounds"].([]any)[0].(map[string]any)
	if uList, ok := ibView["users"].([]any); !ok || len(uList) != 0 {
		t.Fatalf("ConfigView leaked stale user after 1->0 demotion from non-empty raw: %#v", ibView["users"])
	}
	if _, hasManaged := ibView["managed"]; hasManaged {
		t.Fatalf("ConfigView leaked managed flag after 1->0 demotion: %#v", ibView["managed"])
	}
}

func TestXrayZeroUserSSRelayStatsAndUnrelatedVLESSHotUpdates(t *testing.T) {
	logger := slog.New(slog.NewTextHandler(io.Discard, nil))
	stats := fmt.Sprintf("127.0.0.1:%d", testutil.Port(t))
	clash := fmt.Sprintf("127.0.0.1:%d", testutil.Port(t))
	engine := singbox.NewEngine(singbox.Options{StatsAddr: stats, ClashAddr: clash, Logger: logger})
	st := state.New()
	a := New(logger, engine, st, 0, false)
	defer a.Stop()

	privKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	realityPriv := base64.RawURLEncoding.EncodeToString(privKey.Bytes())
	realityPub := base64.RawURLEncoding.EncodeToString(privKey.PublicKey().Bytes())

	tlsMap := testutil.TLS(t)
	cert, err := tls.X509KeyPair(
		[]byte(strings.Join(tlsMap["certificate"].([]string), "\n")),
		[]byte(strings.Join(tlsMap["key"].([]string), "\n")),
	)
	if err != nil {
		t.Fatal(err)
	}
	realityTarget, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{cert},
		NextProtos:   []string{"h2", "http/1.1"},
	})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = realityTarget.Close() })
	go func() {
		for {
			c, acceptErr := realityTarget.Accept()
			if acceptErr != nil {
				return
			}
			go func() { defer c.Close(); _, _ = io.Copy(io.Discard, c) }()
		}
	}()

	ssPort, vlessPort := testutil.Port(t), testutil.Port(t)
	serverPSK := base64.StdEncoding.EncodeToString([]byte("0123456789abcdef0123456789abcdef"))
	echoDest := testutil.Echo(t)

	makeJP4Config := func(ssClients []any) []byte {
		cfg := map[string]any{
			"log": map[string]any{"loglevel": "none"},
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
				},
				map[string]any{
					"tag":      "VLESS_PUBLIC_INBOUND_JP4",
					"listen":   "127.0.0.1",
					"port":     vlessPort,
					"protocol": "vless",
					"settings": map[string]any{
						"clients":    []any{map[string]any{"id": testutil.UUID1, "email": "u1", "flow": "xtls-rprx-vision"}},
						"decryption": "none",
					},
					"streamSettings": map[string]any{
						"network":  "raw",
						"security": "reality",
						"realitySettings": map[string]any{
							"target":      realityTarget.Addr().String(),
							"shortIds":    []any{"010203040506"},
							"privateKey":  realityPriv,
							"serverNames": []any{"next.tama.ac.jp"},
						},
					},
				},
			},
			"outbounds": []any{
				map[string]any{"tag": "DIRECT", "protocol": "freedom"},
				map[string]any{"tag": "BLOCK", "protocol": "blackhole"},
			},
		}
		raw, marshalErr := json.Marshal(cfg)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		return raw
	}

	rawZeroSS := makeJP4Config([]any{})
	if err = a.StartWithForce(rawZeroSS, false); err != nil {
		t.Fatal(err)
	}
	snap, _ := st.Snapshot()
	if _, managed := snap["SS_IN_JP4"]; managed {
		t.Fatal("0-user SS_IN_JP4 must not be enrolled in managed state snapshot")
	}

	startSocksClient := func(outbound map[string]any) int {
		socksPort := testutil.Port(t)
		clientCfg := map[string]any{
			"log":       map[string]any{"disabled": true},
			"inbounds":  []any{map[string]any{"type": "socks", "tag": "in", "listen": "127.0.0.1", "listen_port": socksPort}},
			"outbounds": []any{outbound},
			"route":     map[string]any{"final": outbound["tag"]},
		}
		data, _ := json.Marshal(clientCfg)
		ctx, cancel := context.WithCancel(include.Context(context.Background()))
		opts, parseErr := singJSON.UnmarshalExtendedContext[option.Options](ctx, data)
		if parseErr != nil {
			cancel()
			t.Fatal(parseErr)
		}
		inst, newErr := box.New(box.Options{Context: ctx, Options: opts})
		if newErr != nil {
			cancel()
			t.Fatal(newErr)
		}
		if startErr := inst.Start(); startErr != nil {
			inst.Close()
			cancel()
			t.Fatal(startErr)
		}
		t.Cleanup(func() { _ = inst.Close(); cancel() })
		return socksPort
	}
	socksPing := func(socksPort int) error {
		host, portStr, splitErr := net.SplitHostPort(echoDest)
		if splitErr != nil {
			return splitErr
		}
		var p int
		_, _ = fmt.Sscanf(portStr, "%d", &p)
		ip := net.ParseIP(host).To4()
		c, dialErr := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", socksPort), 2*time.Second)
		if dialErr != nil {
			return dialErr
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(2 * time.Second))
		if _, wErr := c.Write([]byte{0x05, 0x01, 0x00}); wErr != nil {
			return wErr
		}
		greet := make([]byte, 2)
		if _, rErr := io.ReadFull(c, greet); rErr != nil {
			return rErr
		}
		if _, wErr := c.Write([]byte{0x05, 0x01, 0x00, 0x01, ip[0], ip[1], ip[2], ip[3], byte(p >> 8), byte(p)}); wErr != nil {
			return wErr
		}
		rep := make([]byte, 10)
		if _, rErr := io.ReadFull(c, rep); rErr != nil || rep[1] != 0x00 {
			return fmt.Errorf("socks connect failed: err=%v rep=%v", rErr, rep)
		}
		return testutil.Ping(c)
	}

	checkVLESS := func(socksPort int) error {
		// Upstream github.com/sagernet/sing-vmess/vless/vision.go:89 converts a
		// uintptr back to unsafe.Pointer, which triggers Go's -d=checkptr abort
		// when compiled with -race. Under -race we verify the live Reality+uTLS
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
		return socksPing(socksPort)
	}

	vlessSocks := startSocksClient(map[string]any{
		"type": "vless", "tag": "vl-out", "server": "127.0.0.1", "server_port": vlessPort,
		"uuid": testutil.UUID1, "flow": "xtls-rprx-vision",
		"tls": map[string]any{
			"enabled": true, "server_name": "next.tama.ac.jp",
			"utls":    map[string]any{"enabled": true, "fingerprint": "chrome"},
			"reality": map[string]any{"enabled": true, "public_key": realityPub, "short_id": "010203040506"},
		},
	})
	if err = checkVLESS(vlessSocks); err != nil {
		t.Fatalf("VLESS Reality Vision failed: %v", err)
	}

	pskMethod, err := shadowaead_2022.NewWithPassword("2022-blake3-aes-256-gcm", serverPSK, nil)
	if err != nil {
		t.Fatal(err)
	}
	rawRelayConn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", ssPort), 2*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer rawRelayConn.Close()
	activeRelayStream, err := pskMethod.DialConn(rawRelayConn, M.ParseSocksaddr(echoDest))
	if err != nil {
		t.Fatalf("SS_IN_JP4 single-password PSK dial failed: %v", err)
	}
	defer activeRelayStream.Close()
	if err = testutil.Ping(activeRelayStream); err != nil {
		t.Fatalf("SS_IN_JP4 single-password PSK ping failed: %v", err)
	}

	// Verify node inbound stats track SS_IN_JP4 while user counters do not charge relay traffic.
	ibCounters, err := a.Query(context.Background(), []string{"inbound>>>SS_IN_JP4>>>"}, false)
	if err != nil {
		t.Fatal(err)
	}
	var ssTracked int64
	for _, c := range ibCounters {
		ssTracked += c.Value
	}
	if ssTracked < 8 {
		t.Fatalf("expected SS_IN_JP4 inbound stats > 0, got %#v", ibCounters)
	}

	// Unrelated VLESS hot user add/remove must not restart listeners or break active SS_IN_JP4 stream.
	if err = a.UpdateUsers([]state.Update{{
		ID: "u2", HashUUID: testutil.UUID2,
		Memberships: []state.Membership{{Tag: "VLESS_PUBLIC_INBOUND_JP4", Protocol: "vless", User: state.User{ID: "u2", Credential: testutil.UUID2, Flow: "xtls-rprx-vision"}}},
	}}); err != nil {
		t.Fatalf("VLESS hot add failed: %v", err)
	}
	if err = testutil.Ping(activeRelayStream); err != nil {
		t.Fatalf("VLESS hot add interrupted single-password SS_IN_JP4 relay stream: %v", err)
	}
	if err = a.UpdateUsers([]state.Update{{ID: "u2", HashUUID: testutil.UUID2}}); err != nil {
		t.Fatalf("VLESS hot remove failed: %v", err)
	}
	if err = testutil.Ping(activeRelayStream); err != nil {
		t.Fatalf("VLESS hot remove interrupted single-password SS_IN_JP4 relay stream: %v", err)
	}
}
