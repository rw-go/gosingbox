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
