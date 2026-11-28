package config

import (
	"strings"
	"testing"
)

func TestLoadRejectsInvalidNumericEnvironment(t *testing.T) {
	t.Setenv("NODE_PORT", "not-a-port")
	if _, err := Load(); err == nil {
		t.Fatal("Load accepted invalid NODE_PORT")
	}
}

func TestLoadRejectsNegativeDebounce(t *testing.T) {
	t.Setenv("SINGBOX_DEBOUNCE_MS", "-1")
	if _, err := Load(); err == nil {
		t.Fatal("Load accepted negative debounce")
	}
}

func TestLoadNftablesTableNameDefaultAndCustom(t *testing.T) {
	t.Setenv("NFTABLES_TABLE_NAME", "")
	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load empty NFTABLES_TABLE_NAME failed: %v", err)
	}
	if cfg.NftablesTableName != "remnanode" {
		t.Fatalf("NftablesTableName = %q, want remnanode", cfg.NftablesTableName)
	}
	if cfg.SuppressDuplicateInstanceWarning {
		t.Fatal("SuppressDuplicateInstanceWarning = true by default, want false")
	}

	t.Setenv("NFTABLES_TABLE_NAME", "   ")
	cfg, err = Load()
	if err != nil {
		t.Fatalf("Load whitespace NFTABLES_TABLE_NAME failed: %v", err)
	}
	if cfg.NftablesTableName != "remnanode" {
		t.Fatalf("NftablesTableName = %q, want remnanode", cfg.NftablesTableName)
	}

	t.Setenv("NFTABLES_TABLE_NAME", "custom_rw_table")
	t.Setenv("SUPPRESS_DUPLICATE_INSTANCE_WARNING", "true")
	cfg, err = Load()
	if err != nil {
		t.Fatalf("Load custom NFTABLES_TABLE_NAME failed: %v", err)
	}
	if cfg.NftablesTableName != "custom_rw_table" {
		t.Fatalf("NftablesTableName = %q, want custom_rw_table", cfg.NftablesTableName)
	}
	if !cfg.SuppressDuplicateInstanceWarning {
		t.Fatal("SuppressDuplicateInstanceWarning = false, want true")
	}
}

func TestLoadRejectsInvalidNftablesTableName(t *testing.T) {
	for _, bad := range []string{
		"bad;name",
		"bad\n}",
		"123start",
		strings.Repeat("x", 65),
	} {
		t.Run(bad, func(t *testing.T) {
			t.Setenv("NFTABLES_TABLE_NAME", bad)
			if _, err := Load(); err == nil {
				t.Fatalf("Load accepted invalid NFTABLES_TABLE_NAME %q", bad)
			}
		})
	}
}
