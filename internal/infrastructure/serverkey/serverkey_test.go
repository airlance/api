package serverkey

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestGenerateServerKeyPair_RejectsEmptyKeyID(t *testing.T) {
	_, err := GenerateServerKeyPair("")
	if err == nil {
		t.Fatal("expected error for empty keyID, got nil")
	}
}

func TestGenerateServerKeyPair_ProducesDistinctKeysOnEachCall(t *testing.T) {
	a, err := GenerateServerKeyPair("v1")
	if err != nil {
		t.Fatalf("GenerateServerKeyPair failed: %v", err)
	}
	b, err := GenerateServerKeyPair("v1")
	if err != nil {
		t.Fatalf("GenerateServerKeyPair failed: %v", err)
	}

	if string(a.PrivateKey.Bytes()) == string(b.PrivateKey.Bytes()) {
		t.Fatal("two independently generated keypairs produced identical private keys — broken randomness")
	}
}

func TestSaveThenLoadServerKeyPair_Roundtrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server-key.json")

	original, err := GenerateServerKeyPair("v1")
	if err != nil {
		t.Fatalf("GenerateServerKeyPair failed: %v", err)
	}

	if err := SaveServerKeyPair(path, original); err != nil {
		t.Fatalf("SaveServerKeyPair failed: %v", err)
	}

	loaded, err := LoadServerKeyPair(path)
	if err != nil {
		t.Fatalf("LoadServerKeyPair failed: %v", err)
	}

	if loaded.KeyID != original.KeyID {
		t.Fatalf("KeyID mismatch: got %s, want %s", loaded.KeyID, original.KeyID)
	}
	if string(loaded.PrivateKey.Bytes()) != string(original.PrivateKey.Bytes()) {
		t.Fatal("private key mismatch after roundtrip")
	}
	if string(loaded.PublicKey().Bytes()) != string(original.PublicKey().Bytes()) {
		t.Fatal("public key mismatch after roundtrip")
	}
}

func TestFileServerKeyRepository_LoadServerKeyPair(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server-key.json")

	kp, err := GenerateServerKeyPair("v1")
	if err != nil {
		t.Fatalf("GenerateServerKeyPair failed: %v", err)
	}
	if err := SaveServerKeyPair(path, kp); err != nil {
		t.Fatalf("SaveServerKeyPair failed: %v", err)
	}

	repo := NewFileServerKeyRepository(path)
	pub, priv, err := repo.LoadServerKeyPair()
	if err != nil {
		t.Fatalf("LoadServerKeyPair failed: %v", err)
	}

	if string(pub) != string(kp.PublicKey().Bytes()) {
		t.Fatal("public key mismatch")
	}
	if string(priv) != string(kp.PrivateKey.Bytes()) {
		t.Fatal("private key mismatch")
	}
}

func TestSaveServerKeyPair_SetsRestrictivePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file permissions not applicable on windows")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "server-key.json")

	kp, err := GenerateServerKeyPair("v1")
	if err != nil {
		t.Fatalf("GenerateServerKeyPair failed: %v", err)
	}
	if err := SaveServerKeyPair(path, kp); err != nil {
		t.Fatalf("SaveServerKeyPair failed: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}

	got := info.Mode().Perm()
	want := os.FileMode(0o600)
	if got != want {
		t.Fatalf("key file permissions = %o, want %o (private key must not be group/world readable)", got, want)
	}
}

func TestSaveServerKeyPair_OverwritesLoosePermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX file permissions not applicable on windows")
	}

	dir := t.TempDir()
	path := filepath.Join(dir, "server-key.json")

	if err := os.WriteFile(path, []byte("{}"), 0o644); err != nil {
		t.Fatalf("failed to pre-create file: %v", err)
	}

	kp, err := GenerateServerKeyPair("v1")
	if err != nil {
		t.Fatalf("GenerateServerKeyPair failed: %v", err)
	}
	if err := SaveServerKeyPair(path, kp); err != nil {
		t.Fatalf("SaveServerKeyPair failed: %v", err)
	}

	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("Stat failed: %v", err)
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("expected SaveServerKeyPair to tighten permissions to 0600 even for pre-existing file, got %o", got)
	}
}

func TestLoadServerKeyPair_RejectsUnsupportedVersion(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server-key.json")

	kp, err := GenerateServerKeyPair("v1")
	if err != nil {
		t.Fatalf("GenerateServerKeyPair failed: %v", err)
	}
	if err := SaveServerKeyPair(path, kp); err != nil {
		t.Fatalf("SaveServerKeyPair failed: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	raw["version"] = 999
	corrupted, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	if err := os.WriteFile(path, corrupted, 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	if _, err := LoadServerKeyPair(path); err == nil {
		t.Fatal("expected error loading key file with unsupported version, got nil")
	}
}

func TestLoadServerKeyPair_DetectsPublicKeyMismatch(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server-key.json")

	kp, err := GenerateServerKeyPair("v1")
	if err != nil {
		t.Fatalf("GenerateServerKeyPair failed: %v", err)
	}
	if err := SaveServerKeyPair(path, kp); err != nil {
		t.Fatalf("SaveServerKeyPair failed: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	raw["public_key_hex"] = "0000000000000000000000000000000000000000000000000000000000000000"
	corrupted, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	if err := os.WriteFile(path, corrupted, 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	if _, err := LoadServerKeyPair(path); err == nil {
		t.Fatal("expected error loading key file with mismatched public key, got nil")
	}
}

func TestLoadServerKeyPair_RejectsMissingKeyID(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "server-key.json")

	kp, err := GenerateServerKeyPair("v1")
	if err != nil {
		t.Fatalf("GenerateServerKeyPair failed: %v", err)
	}
	if err := SaveServerKeyPair(path, kp); err != nil {
		t.Fatalf("SaveServerKeyPair failed: %v", err)
	}

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}
	var raw map[string]interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		t.Fatalf("Unmarshal failed: %v", err)
	}
	raw["key_id"] = ""
	corrupted, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("Marshal failed: %v", err)
	}
	if err := os.WriteFile(path, corrupted, 0o600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	if _, err := LoadServerKeyPair(path); err == nil {
		t.Fatal("expected error loading key file with empty key_id, got nil")
	}
}

func TestLoadServerKeyPair_NonexistentFile(t *testing.T) {
	_, err := LoadServerKeyPair(filepath.Join(t.TempDir(), "does-not-exist.json"))
	if err == nil {
		t.Fatal("expected error loading nonexistent file, got nil")
	}
}
