package singbox

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"

	"github.com/gofrs/uuid/v5"
	"github.com/rwnode/rwnode-gosingbox/internal/state"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/service"
)

type userApply struct {
	tag, kind      string
	next, previous any
	apply          func(any) error
}

// ApplyUsers prevalidates every target, then applies under the engine lock.
// On failure restore all attempted targets; an unsuccessful rollback stops the
// data plane so callers cannot mistake a partially applied state for success.
func (e *Engine) ApplyUsers(next state.Snapshot) error {
	if err := next.Validate(); err != nil {
		return err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.box == nil || !e.online {
		return fmt.Errorf("not running")
	}
	previous, err := state.FromConfig(e.currentConfig)
	if err != nil {
		return err
	}
	if !reflect.DeepEqual(previous.Tags(), next.Tags()) {
		return fmt.Errorf("managed inbound set changed")
	}
	im := service.FromContext[adapter.InboundManager](e.ctx)
	if im == nil {
		return fmt.Errorf("inbound manager unavailable")
	}
	var changes []userApply
	for _, tag := range next.Tags() {
		current := next[tag]
		old := previous[tag]
		if current.Protocol != old.Protocol || current.Cipher != old.Cipher {
			return fmt.Errorf("inbound protocol changed: %q", tag)
		}
		// HashUUID is a control-plane index, not part of the data-plane user.
		users, err := wireUsers(current, next.OrderedUsers(tag))
		if err != nil {
			return fmt.Errorf("inbound %q: %w", tag, err)
		}
		before, err := wireUsers(old, previous.OrderedUsers(tag))
		if err != nil {
			return err
		}
		if reflect.DeepEqual(users, before) {
			continue
		}
		ib, ok := im.Get(tag)
		if !ok {
			return fmt.Errorf("inbound missing: %q", tag)
		}
		change := userApply{tag: tag, kind: current.Protocol, next: users, previous: before}
		switch current.Protocol {
		case "vless":
			u, ok := ib.(adapter.UpdatableInbound[option.VLESSUser])
			if !ok {
				return fmt.Errorf("VLESS inbound not updatable: %q", tag)
			}
			change.apply = func(v any) error { return u.UpdateUsers(v.([]option.VLESSUser)) }
		case "shadowsocks22":
			u, ok := ib.(adapter.UpdatableShadowsocksInbound)
			if !ok {
				return fmt.Errorf("SS2022 inbound not updatable: %q", tag)
			}
			change.kind = "shadowsocks"
			change.apply = func(v any) error { return u.UpdateUsersByOptions(v.([]option.ShadowsocksUser)) }
		case "anytls":
			u, ok := ib.(adapter.UpdatableInbound[option.AnyTLSUser])
			if !ok {
				return fmt.Errorf("AnyTLS inbound not updatable: %q", tag)
			}
			change.apply = func(v any) error { return u.UpdateUsers(v.([]option.AnyTLSUser)) }
		}
		changes = append(changes, change)
	}
	if err, rollbackFailed := applyUserChanges(changes); err != nil {
		if rollbackFailed {
			e.stopLocked()
			e.currentConfig = nil
		}
		return err
	}
	for _, change := range changes {
		e.updateCurrentUsersLocked(change.kind, change.tag, change.next)
	}
	if server := service.FromContext[adapter.V2RayServer](e.ctx); server != nil {
		server.UpdateUsers(next.Names())
	}
	return nil
}
func applyUserChanges(changes []userApply) (error, bool) {
	for i, change := range changes {
		if err := change.apply(change.next); err != nil {
			failures := []error{fmt.Errorf("update inbound %q: %w", change.tag, err)}
			failed := false
			for j := i; j >= 0; j-- {
				if restore := changes[j].apply(changes[j].previous); restore != nil {
					failed = true
					failures = append(failures, fmt.Errorf("rollback inbound %q: %w", changes[j].tag, restore))
				}
			}
			return errors.Join(failures...), failed
		}
	}
	return nil, false
}
func wireUsers(inbound state.Inbound, users []state.User) (any, error) {
	switch inbound.Protocol {
	case "vless":
		result := make([]option.VLESSUser, 0, len(users))
		for _, u := range users {
			if _, err := uuid.FromString(u.Credential); err != nil {
				return nil, fmt.Errorf("invalid VLESS UUID for user %q", u.ID)
			}
			result = append(result, option.VLESSUser{Name: u.ID, UUID: u.Credential, Flow: u.Flow})
		}
		return result, nil
	case "shadowsocks22":
		result := make([]option.ShadowsocksUser, 0, len(users))
		for _, u := range users {
			key, err := base64.StdEncoding.DecodeString(u.Credential)
			minimum := 32
			if inbound.Cipher == "2022-blake3-aes-128-gcm" {
				minimum = 16
			}
			if err != nil || len(key) < minimum {
				return nil, fmt.Errorf("invalid SS2022 key for user %q", u.ID)
			}
			result = append(result, option.ShadowsocksUser{Name: u.ID, Password: u.Credential})
		}
		return result, nil
	case "anytls":
		result := make([]option.AnyTLSUser, 0, len(users))
		for _, u := range users {
			result = append(result, option.AnyTLSUser{Name: u.ID, Password: u.Credential})
		}
		return result, nil
	}
	return nil, fmt.Errorf("unsupported protocol")
}

// SameBase compares effective configs excluding only managed user lists and
// the statistics whitelist. Listener, TLS, routing and other changes still restart.
func (e *Engine) SameBase(next map[string]any) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.online && e.currentConfig != nil && bytes.Equal(configBase(e.currentConfig), configBase(next))
}
func configBase(config map[string]any) []byte {
	raw, _ := json.Marshal(config)
	var copy map[string]any
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	_ = decoder.Decode(&copy)
	if inbounds, ok := copy["inbounds"].([]any); ok {
		for _, item := range inbounds {
			ib := item.(map[string]any)
			kind := ib["type"]
			_, hasUsers := ib["users"]
			if kind == "vless" || kind == "anytls" || (kind == "shadowsocks" && (hasUsers || ib["managed"] == true)) {
				delete(ib, "users")
				if kind == "shadowsocks" {
					ib["managed"] = true
				}
			}
		}
	}
	if exp, ok := copy["experimental"].(map[string]any); ok {
		if api, ok := exp["v2ray_api"].(map[string]any); ok {
			if stats, ok := api["stats"].(map[string]any); ok {
				delete(stats, "users")
			}
		}
	}
	result, _ := json.Marshal(copy)
	return result
}

// ValidateConfig checks the actual embedded option schema and all managed user
// credentials before a native full push is allowed to replace a running core.
func (e *Engine) ValidateConfig(config map[string]any) error {
	if _, _, err := e.parseOptions(config); err != nil {
		return err
	}
	users, err := state.FromConfig(config)
	if err != nil {
		return err
	}
	for _, tag := range users.Tags() {
		if _, err = wireUsers(users[tag], users.OrderedUsers(tag)); err != nil {
			return fmt.Errorf("inbound %q: %w", tag, err)
		}
	}
	return nil
}
