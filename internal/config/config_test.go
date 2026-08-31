package config

import "testing"

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
