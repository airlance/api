package nodeid_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/airlance/api/internal/infrastructure/nodeid"
)

func TestLoad_GeneratesAndPersists(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "data", "node_id")

	id1, err := nodeid.Load(path)
	if err != nil {
		t.Fatalf("first Load failed: %v", err)
	}
	if id1 == "" {
		t.Fatal("expected non-empty node_id")
	}

	id2, err := nodeid.Load(path)
	if err != nil {
		t.Fatalf("second Load failed: %v", err)
	}
	if id1 != id2 {
		t.Fatalf("expected stable node_id: got %q then %q", id1, id2)
	}
}

func TestLoad_ReadsExistingFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "node_id")
	want := "my-custom-node-id"

	if err := os.WriteFile(path, []byte(want+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	got, err := nodeid.Load(path)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}
	if got != want {
		t.Fatalf("expected %q, got %q", want, got)
	}
}
