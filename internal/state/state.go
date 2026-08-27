// Package state holds the desired sing-box state: the latest panel config and
// the current VLESS/SS user set. It is the Go equivalent of the Node.js
// InternalService (source of truth for the user-change pipeline).
package state

import (
	"encoding/json"
	"sync"

	"rwnode-singbox/internal/transpiler"
)

// State is the thread-safe desired-state store.
type State struct {
	mu sync.RWMutex

	rawConfig   []byte
	hasConfig   bool
	vlessUsers  []transpiler.VlessUser // desired VLESS users
	inboundTags []string               // registered inbound tags
}

// New creates an empty state.
func New() *State {
	return &State{}
}

// SetRawConfig stores the panel xray config and rebuilds the user set from it.
func (s *State) SetRawConfig(raw []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rawConfig = raw
	s.hasConfig = true
	var cfg map[string]any
	if err := json.Unmarshal(raw, &cfg); err == nil {
		s.vlessUsers = transpiler.UsersFromConfig(cfg)
	} else {
		s.vlessUsers = nil
	}
}

// RawConfig returns the last panel config.
func (s *State) RawConfig() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if !s.hasConfig {
		return nil
	}
	out := make([]byte, len(s.rawConfig))
	copy(out, s.rawConfig)
	return out
}

// HasConfig reports whether a panel config has been received.
func (s *State) HasConfig() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.hasConfig
}

// VlessUsers returns the current desired VLESS user set.
func (s *State) VlessUsers() []transpiler.VlessUser {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]transpiler.VlessUser, len(s.vlessUsers))
	copy(out, s.vlessUsers)
	return out
}

// AddUser adds or updates a desired VLESS user by UUID.
func (s *State) AddUser(u transpiler.VlessUser) {
	s.mu.Lock()
	defer s.mu.Unlock()
	u.Flow = transpiler.NormalizeFlow(u.Flow)
	for i := range s.vlessUsers {
		if s.vlessUsers[i].UUID == u.UUID {
			s.vlessUsers[i] = u
			return
		}
	}
	s.vlessUsers = append(s.vlessUsers, u)
}

// RemoveUser removes a user by UUID.
func (s *State) RemoveUser(uuid string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	for i := range s.vlessUsers {
		if s.vlessUsers[i].UUID == uuid {
			s.vlessUsers = append(s.vlessUsers[:i], s.vlessUsers[i+1:]...)
			return true
		}
	}
	return false
}

// SetInboundTags records the inbound tags from the last transpile.
func (s *State) SetInboundTags(tags []string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.inboundTags = append([]string(nil), tags...)
}

// InboundTags returns the registered inbound tags.
func (s *State) InboundTags() []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]string, len(s.inboundTags))
	copy(out, s.inboundTags)
	return out
}
