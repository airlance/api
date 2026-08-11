package transport

import (
	"testing"
)

func TestConnectionRegistry_RegisterAndGet(t *testing.T) {
	reg := NewConnectionRegistry()

	active := reg.Register(nil)
	if active.ID == "" {
		t.Fatal("expected non-empty connection ID")
	}

	got, ok := reg.Get(active.ID)
	if !ok {
		t.Fatalf("expected to find connection with ID %s", active.ID)
	}
	if got.ID != active.ID {
		t.Fatalf("got ID %s, want %s", got.ID, active.ID)
	}

	if reg.Count() != 1 {
		t.Fatalf("count = %d, want 1", reg.Count())
	}

	reg.Unregister(active.ID)
	if _, ok := reg.Get(active.ID); ok {
		t.Fatal("expected connection to be unregistered")
	}
	if reg.Count() != 0 {
		t.Fatalf("count = %d, want 0", reg.Count())
	}
}
