// Package state stores the last applied configuration and per-inbound users.
// Candidate snapshots are built and validated before applying or committing.
package state

import (
	"encoding/json"
	"fmt"
	"github.com/rwnode/rwnode-gosingbox/internal/contract"
	"slices"
	"sync"
)

type User struct {
	ID         string
	Credential string
	Flow       string
	HashUUID   string
}
type Inbound struct {
	Cipher   string
	Protocol string
	Users    map[string]User
}
type Snapshot map[string]Inbound

type Membership struct {
	Tag, Protocol string
	User          User
}

// Update replaces one user's entire authorization set on this node.
// Empty Memberships revoke that user without clearing unrelated users.
type Update struct {
	ID           string
	HashUUID     string
	PreviousUUID string
	Memberships  []Membership
}

type State struct {
	mu         sync.RWMutex
	raw        []byte
	users      Snapshot
	generation uint64
	format     contract.ConfigFormat
}

func New() *State { return &State{users: Snapshot{}} }
func (s *State) RawConfig() []byte {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return append([]byte(nil), s.raw...)
}
func (s *State) HasConfig() bool { s.mu.RLock(); defer s.mu.RUnlock(); return s.raw != nil }
func (s *State) Snapshot() (Snapshot, uint64) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.users.Clone(), s.generation
}
func (s *State) Format() contract.ConfigFormat {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.format.WithDefault()
}
func (s *State) Commit(raw []byte, users Snapshot, format contract.ConfigFormat) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.raw = append([]byte(nil), raw...)
	s.users = users.Clone()
	s.generation++
	s.format = format
}
func (s *State) CommitUsers(users Snapshot, generation uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if generation != s.generation {
		return fmt.Errorf("configuration generation changed")
	}
	s.users = users.Clone()
	return nil
}
func (s Snapshot) Clone() Snapshot {
	out := Snapshot{}
	for tag, ib := range s {
		users := map[string]User{}
		for id, u := range ib.Users {
			users[id] = u
		}
		out[tag] = Inbound{Protocol: ib.Protocol, Cipher: ib.Cipher, Users: users}
	}
	return out
}
func (s Snapshot) Names() []string {
	set := map[string]bool{}
	for _, ib := range s {
		for id := range ib.Users {
			set[id] = true
		}
	}
	out := make([]string, 0, len(set))
	for id := range set {
		out = append(out, id)
	}
	slices.Sort(out)
	return out
}
func (s Snapshot) Tags() []string {
	out := make([]string, 0, len(s))
	for tag := range s {
		out = append(out, tag)
	}
	slices.Sort(out)
	return out
}
func (s Snapshot) OrderedUsers(tag string) []User {
	ib := s[tag]
	ids := make([]string, 0, len(ib.Users))
	for id := range ib.Users {
		ids = append(ids, id)
	}
	slices.Sort(ids)
	out := make([]User, 0, len(ids))
	for _, id := range ids {
		out = append(out, ib.Users[id])
	}
	return out
}
func (s Snapshot) ResolveID(id string, aliases ...string) (string, error) {
	found := id
	for _, ib := range s {
		for uid, u := range ib.Users {
			for _, alias := range aliases {
				if alias != "" && (u.Credential == alias || u.HashUUID == alias) {
					if found != "" && found != uid {
						return "", fmt.Errorf("user identity conflicts with credential index")
					}
					found = uid
				}
			}
		}
	}
	if found == "" {
		return "", fmt.Errorf("cannot resolve stable user identity")
	}
	return found, nil
}
func (s Snapshot) Replace(updates []Update) (Snapshot, error) {
	next := s.Clone()
	seen := map[string]bool{}
	for _, update := range updates {
		id, err := s.ResolveID(update.ID, update.PreviousUUID, update.HashUUID)
		if err != nil {
			return nil, err
		}
		if seen[id] {
			return nil, fmt.Errorf("duplicate user in update: %q", id)
		}
		seen[id] = true
		for _, ib := range next {
			delete(ib.Users, id)
		}
		tags := map[string]bool{}
		for _, member := range update.Memberships {
			ib, ok := next[member.Tag]
			if !ok || member.Tag == "" {
				return nil, fmt.Errorf("unknown managed inbound: %q", member.Tag)
			}
			if ib.Protocol != member.Protocol {
				return nil, fmt.Errorf("inbound protocol mismatch: %q", member.Tag)
			}
			if tags[member.Tag] {
				return nil, fmt.Errorf("duplicate inbound membership: %q", member.Tag)
			}
			tags[member.Tag] = true
			if member.User.ID != id {
				return nil, fmt.Errorf("inconsistent user identity")
			}
			user := member.User
			user.HashUUID = update.HashUUID
			ib.Users[id] = user
		}
	}
	if err := next.Validate(); err != nil {
		return nil, err
	}
	return next, nil
}
func (s Snapshot) Validate() error {
	for tag, ib := range s {
		if tag == "" {
			return fmt.Errorf("empty inbound tag")
		}
		if ib.Protocol != "vless" && ib.Protocol != "shadowsocks22" && ib.Protocol != "anytls" {
			return fmt.Errorf("unsupported managed protocol: %q", ib.Protocol)
		}
		credentials := map[string]bool{}
		for id, u := range ib.Users {
			if id == "" || id != u.ID || u.Credential == "" {
				return fmt.Errorf("invalid user identity or credential on %q", tag)
			}
			if credentials[u.Credential] {
				return fmt.Errorf("duplicate credential on %q", tag)
			}
			credentials[u.Credential] = true
			if ib.Protocol == "vless" && u.Flow != "" && u.Flow != "xtls-rprx-vision" {
				return fmt.Errorf("unsupported VLESS flow on %q", tag)
			}
		}
	}
	return nil
}

// FromConfig extracts managed users from already prepared sing-box JSON. A
// single-password Shadowsocks inbound is intentionally not a managed user list.
func FromConfig(config map[string]any) (Snapshot, error) {
	data, err := json.Marshal(config)
	if err != nil {
		return nil, err
	}
	var cfg struct {
		Inbounds []struct {
			Type, Tag, Method string
			Managed           bool
			Users             []struct{ Name, UUID, Password, Flow string }
		} `json:"inbounds"`
	}
	if err = json.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}
	result := Snapshot{}
	for _, ib := range cfg.Inbounds {
		protocol := ib.Type
		if protocol == "shadowsocks" {
			if len(ib.Users) == 0 && !ib.Managed {
				continue
			}
			protocol = "shadowsocks22"
		}
		if protocol != "vless" && protocol != "shadowsocks22" && protocol != "anytls" {
			continue
		}
		if _, ok := result[ib.Tag]; ok {
			return nil, fmt.Errorf("duplicate inbound tag: %q", ib.Tag)
		}
		users := map[string]User{}
		for _, u := range ib.Users {
			credential := u.Password
			hash := ""
			if protocol == "vless" {
				credential = u.UUID
				hash = u.UUID
			}
			if protocol == "anytls" {
				hash = u.Password
			}
			if _, ok := users[u.Name]; ok {
				return nil, fmt.Errorf("duplicate user identity on %q", ib.Tag)
			}
			users[u.Name] = User{ID: u.Name, Credential: credential, Flow: u.Flow, HashUUID: hash}
		}
		result[ib.Tag] = Inbound{Protocol: protocol, Cipher: ib.Method, Users: users}
	}
	return result, result.Validate()
}

// WriteConfig updates only managed user lists in a decoded native config view.
// The caller owns config; the snapshot is not modified.
func (s Snapshot) WriteConfig(config map[string]any) {
	inbounds, _ := config["inbounds"].([]any)
	for _, value := range inbounds {
		inbound, ok := value.(map[string]any)
		if !ok {
			continue
		}
		tag, _ := inbound["tag"].(string)
		managed, ok := s[tag]
		if !ok {
			continue
		}
		users := make([]any, 0, len(managed.Users))
		for _, u := range s.OrderedUsers(tag) {
			user := map[string]any{"name": u.ID}
			if managed.Protocol == "vless" {
				user["uuid"] = u.Credential
				user["flow"] = u.Flow
			} else {
				user["password"] = u.Credential
			}
			users = append(users, user)
		}
		inbound["users"] = users
		if managed.Protocol == "shadowsocks22" {
			if len(users) == 0 {
				inbound["managed"] = true
			} else {
				delete(inbound, "managed")
			}
		}
	}
}
