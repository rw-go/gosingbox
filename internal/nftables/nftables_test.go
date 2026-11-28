package nftables

import (
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestSetForAcceptsIPAndCIDR(t *testing.T) {
	for _, tc := range []struct {
		input string
		want  string
	}{
		{input: "192.0.2.1", want: "v4"},
		{input: "192.0.2.0/24", want: "v4"},
		{input: "2001:db8::1", want: "v6"},
		{input: "2001:db8::/32", want: "v6"},
	} {
		got := setFor(tc.input, "v4", "v6")
		if got != tc.want {
			t.Errorf("setFor(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestSetForRejectsInvalidAddress(t *testing.T) {
	if got := setFor("not-an-address", "v4", "v6"); got != "" {
		t.Fatalf("setFor invalid address = %q, want empty", got)
	}
}

func TestBatchElements(t *testing.T) {
	got := batchElements([]string{"192.0.2.1", "2001:db8::1"})
	if want := "{ 192.0.2.1, 2001:db8::1 }"; got != want {
		t.Fatalf("batchElements = %q, want %q", got, want)
	}
}

func TestValidateTableNameDefaultsAndValidIdentifiers(t *testing.T) {
	max63 := "a" + strings.Repeat("b", 62)
	for _, tc := range []struct {
		name  string
		input string
		want  string
	}{
		{name: "empty", input: "", want: DefaultTableName},
		{name: "spaces", input: "   ", want: DefaultTableName},
		{name: "tabs-and-newlines-only", input: "\t \n", want: DefaultTableName},
		{name: "default", input: "remnanode", want: "remnanode"},
		{name: "custom", input: "custom_rw_table", want: "custom_rw_table"},
		{name: "underscore-and-dash", input: "_node-2_fw", want: "_node-2_fw"},
		{name: "trimmed-spaces", input: "  custom_rw_table  ", want: "custom_rw_table"},
		{name: "max-63-chars", input: max63, want: max63},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, err := ValidateTableName(tc.input)
			if err != nil {
				t.Fatalf("ValidateTableName(%q) unexpected error: %v", tc.input, err)
			}
			if got != tc.want {
				t.Fatalf("ValidateTableName(%q) = %q, want %q", tc.input, got, tc.want)
			}
		})
	}
}

func TestValidateAndNewRejectInvalidOrInjectionTableNames(t *testing.T) {
	invalid := []struct {
		name  string
		input string
	}{
		{name: "semicolon-injection", input: "bad;name"},
		{name: "newline-brace-injection", input: "bad\n}"},
		{name: "trailing-newline", input: "remnanode\n"},
		{name: "carriage-return", input: "bad\rname"},
		{name: "starts-with-digit", input: "123start"},
		{name: "starts-with-dash", input: "-dashstart"},
		{name: "contains-space", input: "bad name"},
		{name: "contains-slash", input: "bad/name"},
		{name: "contains-braces", input: "bad{name}"},
		{name: "contains-quote", input: `bad"name`},
		{name: "64-chars-over-upstream-63-limit", input: strings.Repeat("a", 64)},
		{name: "over-64-chars", input: strings.Repeat("a", 65)},
	}

	for _, tc := range invalid {
		t.Run(tc.name, func(t *testing.T) {
			if got, err := ValidateTableName(tc.input); err == nil {
				t.Fatalf("ValidateTableName(%q) = %q, expected error", tc.input, got)
			}
			called := false
			mgr, err := New(false, WithTableName(tc.input), WithCommandRunner(func(args ...string) ([]byte, error) {
				called = true
				return nil, nil
			}))
			if err == nil || mgr != nil {
				t.Fatalf("New(WithTableName(%q)) = (%v, %v), expected error", tc.input, mgr, err)
			}
			if called {
				t.Fatalf("New(WithTableName(%q)) executed nft runner despite invalid table name", tc.input)
			}
		})
	}

	// Defense-in-depth: even an unconstructed Manager struct with an injected
	// tableName must refuse to run commands.
	called := false
	raw := &Manager{
		tableName: "bad\n}",
		available: true,
		runner: func(args ...string) ([]byte, error) {
			called = true
			return nil, nil
		},
	}
	if err := raw.CreateTable(); err == nil {
		t.Fatal("CreateTable accepted unvalidated Manager.tableName")
	}
	if err := raw.BlockIP("192.0.2.1", 60); err == nil {
		t.Fatal("BlockIP accepted unvalidated Manager.tableName")
	}
	if err := raw.UnblockIPs([]string{"192.0.2.1"}); err == nil {
		t.Fatal("UnblockIPs accepted unvalidated Manager.tableName")
	}
	if err := raw.AddIngressIPs([]string{"192.0.2.1"}); err == nil {
		t.Fatal("AddIngressIPs accepted unvalidated Manager.tableName")
	}
	if err := raw.AddEgressIPs([]string{"192.0.2.1"}); err == nil {
		t.Fatal("AddEgressIPs accepted unvalidated Manager.tableName")
	}
	if err := raw.AddEgressPorts([]int{443}); err == nil {
		t.Fatal("AddEgressPorts accepted unvalidated Manager.tableName")
	}
	if called {
		t.Fatal("unvalidated Manager executed runner")
	}
}

func TestDefaultTableNameWhenOmittedOrEmpty(t *testing.T) {
	for _, tc := range []struct {
		name string
		opts []Option
	}{
		{name: "omitted", opts: nil},
		{name: "empty", opts: []Option{WithTableName("")}},
		{name: "whitespace", opts: []Option{WithTableName("   ")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var calls [][]string
			opts := append([]Option{}, tc.opts...)
			opts = append(opts, WithCommandRunner(func(args ...string) ([]byte, error) {
				calls = append(calls, append([]string(nil), args...))
				return nil, nil
			}))

			m, err := New(false, opts...)
			if err != nil {
				t.Fatalf("New failed: %v", err)
			}
			if !m.Available() {
				t.Fatal("expected manager to be available")
			}
			if got := m.TableName(); got != "remnanode" {
				t.Fatalf("TableName() = %q, want remnanode", got)
			}

			calls = nil
			if err := m.CreateTable(); err != nil {
				t.Fatalf("CreateTable failed: %v", err)
			}
			if len(calls) == 0 {
				t.Fatal("expected nft commands to be recorded")
			}
			for i, args := range calls {
				if len(args) < 4 || args[2] != "inet" || args[3] != "remnanode" {
					t.Fatalf("call[%d] = %q, expected inet remnanode", i, args)
				}
			}
		})
	}
}

func TestCustomTableNamePropagatedAcrossAllOperations(t *testing.T) {
	const customTable = "custom_rw_table"
	var calls [][]string
	failNextBatch := false

	m, err := New(
		true, // acceptReplyTraffic = true (NFTABLES_ACCEPT_REPLY_TRAFFIC)
		WithTableName(customTable),
		WithCommandRunner(func(args ...string) ([]byte, error) {
			calls = append(calls, append([]string(nil), args...))
			if failNextBatch && strings.Contains(args[len(args)-1], ",") {
				failNextBatch = false
				return []byte("Error: Could not process rule: No such file or directory"), fmt.Errorf("exit status 1")
			}
			return nil, nil
		}),
	)
	if err != nil {
		t.Fatalf("New failed: %v", err)
	}
	if got := m.TableName(); got != customTable {
		t.Fatalf("TableName() = %q, want %q", got, customTable)
	}

	// Discard initial capability probe ("list tables").
	if !reflect.DeepEqual(calls, [][]string{{"list", "tables"}}) {
		t.Fatalf("unexpected probe calls: %#v", calls)
	}
	calls = nil

	if err := m.CreateTable(); err != nil {
		t.Fatalf("CreateTable: %v", err)
	}

	var sawReplyRule bool
	var replyIdx, firstEgressDropIdx int = -1, -1
	for i, args := range calls {
		joined := strings.Join(args, " ")
		if joined == "add rule inet "+customTable+" output ct state established,related accept" {
			sawReplyRule = true
			replyIdx = i
		}
		if firstEgressDropIdx == -1 && strings.Contains(joined, "daddr @egress-filter-ip drop") {
			firstEgressDropIdx = i
		}
	}
	if !sawReplyRule {
		t.Fatalf("missing NFTABLES_ACCEPT_REPLY_TRAFFIC rule on %s; calls=%#v", customTable, calls)
	}
	if replyIdx >= firstEgressDropIdx {
		t.Fatalf("reply-traffic rule index %d must precede egress drop rule index %d", replyIdx, firstEgressDropIdx)
	}

	if err := m.BlockIP("198.51.100.7", 3600); err != nil {
		t.Fatalf("BlockIP v4: %v", err)
	}
	if err := m.BlockIP("2001:db8::7", 0); err != nil {
		t.Fatalf("BlockIP v6: %v", err)
	}
	if err := m.AddIngressIPs([]string{"192.0.2.0/24", "2001:db8::/32"}); err != nil {
		t.Fatalf("AddIngressIPs: %v", err)
	}
	if err := m.AddEgressIPs([]string{"203.0.113.10", "2001:db8:1::10"}); err != nil {
		t.Fatalf("AddEgressIPs: %v", err)
	}
	if err := m.AddEgressPorts([]int{25, 465, 0, 70000}); err != nil {
		t.Fatalf("AddEgressPorts: %v", err)
	}
	// Exercise both batch delete and single-element retry fallback on customTable.
	failNextBatch = true
	if err := m.UnblockIPs([]string{"198.51.100.7", "198.51.100.8", "2001:db8::7"}); err != nil {
		t.Fatalf("UnblockIPs: %v", err)
	}

	for i, args := range calls {
		joined := strings.Join(args, " ")
		if strings.Contains(joined, DefaultTableName) {
			t.Fatalf("call[%d] leaked default table name %q: %v", i, DefaultTableName, args)
		}
		// Every command after the initial probe targets `<verb> <obj> inet <customTable> ...`.
		if len(args) < 4 || args[2] != "inet" || args[3] != customTable {
			t.Fatalf("call[%d] did not target inet %s: %v", i, customTable, args)
		}
	}
}
