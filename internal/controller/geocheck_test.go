package controller

import "testing"

func TestCappedBufferWithinLimit(t *testing.T) {
	var c cappedBuffer
	c.max = 16
	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got := string(c.Bytes()); got != "hello" {
		t.Fatalf("got %q", got)
	}
}

func TestCappedBufferExceedsCancels(t *testing.T) {
	var c cappedBuffer
	c.max = 10
	cancelled := false
	c.cancel = func() { cancelled = true }

	if _, err := c.Write([]byte("hello")); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if _, err := c.Write([]byte("toolong")); err == nil {
		t.Fatal("expected error when exceeding limit")
	}
	if !c.exceeded {
		t.Fatal("expected exceeded flag")
	}
	if !cancelled {
		t.Fatal("expected cancel callback")
	}
}

func TestResolveGeocheckBind(t *testing.T) {
	bind, err := resolveGeocheckBind("192.0.2.1", "does-not-matter")
	if err != nil || bind != "192.0.2.1" {
		t.Fatalf("IP bind = %q, %v", bind, err)
	}
	if _, err := resolveGeocheckBind("not-an-ip", ""); err == nil {
		t.Fatal("expected invalid IP error")
	}
	if _, err := resolveGeocheckBind("", "__does_not_exist__"); err == nil {
		t.Fatal("expected missing interface error")
	}
}
