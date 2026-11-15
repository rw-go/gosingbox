package state

import (
	"github.com/rwnode/rwnode-gosingbox/internal/contract"
	"reflect"
	"testing"
)

func fixture() Snapshot {
	return Snapshot{
		"a": {Protocol: "vless", Users: map[string]User{"1": {ID: "1", Credential: "old", HashUUID: "old"}, "2": {ID: "2", Credential: "other"}}},
		"b": {Protocol: "vless", Users: map[string]User{"1": {ID: "1", Credential: "old", HashUUID: "old"}}},
		"c": {Protocol: "anytls", Users: map[string]User{"1": {ID: "1", Credential: "old", HashUUID: "old"}}},
	}
}
func TestReplacementIsolationRotationAndRetry(t *testing.T) {
	original := fixture()
	updates := []Update{{ID: "1", PreviousUUID: "old", HashUUID: "new", Memberships: []Membership{
		{Tag: "b", Protocol: "vless", User: User{ID: "1", Credential: "new"}},
		{Tag: "c", Protocol: "anytls", User: User{ID: "1", Credential: "new"}},
	}}}
	next, err := original.Replace(updates)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := next["a"].Users["1"]; ok {
		t.Fatal("old membership retained")
	}
	if len(next["a"].Users) != 1 || next["a"].Users["2"].Credential != "other" {
		t.Fatal("unaffected user changed")
	}
	if next["c"].Users["1"].Credential != "new" || next["b"].Users["1"].Credential != "new" {
		t.Fatal("incomplete rotation")
	}
	retry, err := next.Replace(updates)
	if err != nil || !reflect.DeepEqual(retry, next) {
		t.Fatalf("retry: %v", err)
	}
	if original["a"].Users["1"].Credential != "old" {
		t.Fatal("mutated source snapshot")
	}
	removed, err := next.Replace([]Update{{ID: "1", HashUUID: "new"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(removed["b"].Users) != 0 || len(removed["c"].Users) != 0 || len(removed["a"].Users) != 1 {
		t.Fatal("removal scope incorrect")
	}
}
func TestWholeBatchPrevalidation(t *testing.T) {
	original := fixture()
	for _, bad := range []Update{
		{ID: "2", Memberships: []Membership{{Tag: "missing", Protocol: "vless", User: User{ID: "2", Credential: "x"}}}},
		{ID: "2", Memberships: []Membership{{Tag: "a", Protocol: "anytls", User: User{ID: "2", Credential: "x"}}}},
		{ID: "2", Memberships: []Membership{{Tag: "b", Protocol: "vless", User: User{ID: "different", Credential: "x"}}}},
	} {
		if _, err := original.Replace([]Update{{ID: "1"}, bad}); err == nil {
			t.Fatal("bad batch accepted")
		}
		if !reflect.DeepEqual(original, fixture()) {
			t.Fatal("partial batch mutation")
		}
	}
}
func TestCredentialAliasAndAmbiguity(t *testing.T) {
	original := fixture()
	next, err := original.Replace([]Update{{HashUUID: "old"}})
	if err != nil {
		t.Fatal(err)
	}
	if len(next["b"].Users) != 0 {
		t.Fatal("alias failed")
	}
	if _, err = original.Replace([]Update{{ID: "2", HashUUID: "old"}}); err == nil {
		t.Fatal("cross-user alias accepted")
	}
}
func TestCommittedSnapshotsAreCopiedAndGenerationChecked(t *testing.T) {
	st := New()
	raw := []byte(`{"inbounds":[]}`)
	users := fixture()
	st.Commit(raw, users, contract.XrayConfig)
	raw[0] = 'x'
	delete(users["a"].Users, "1")
	snapshot, generation := st.Snapshot()
	delete(snapshot["b"].Users, "1")
	fresh, _ := st.Snapshot()
	if len(fresh["b"].Users) != 1 || len(fresh["a"].Users) != 2 || st.RawConfig()[0] != '{' {
		t.Fatal("aliased state")
	}
	st.Commit([]byte(`{}`), fixture(), contract.SingBoxConfig)
	if err := st.CommitUsers(snapshot, generation); err == nil {
		t.Fatal("stale generation applied")
	}
}
