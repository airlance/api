package crypto

import (
	"testing"

	"airlance.org/api/internal/config"
)

func TestGenerateOpaqueToken(t *testing.T) {
	tok1, hash1, err := GenerateOpaqueToken(32)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if tok1 == "" || len(hash1) != 32 {
		t.Fatalf("invalid token or hash length: len=%d", len(hash1))
	}

	tok2, hash2, _ := GenerateOpaqueToken(32)
	if tok1 == tok2 {
		t.Errorf("expected unique tokens")
	}

	// Validate hash match
	expectedHash := HashToken(tok1)
	if !ConstantTimeCompareBytes(hash1, expectedHash) {
		t.Errorf("computed hash does not match returned hash")
	}
	if ConstantTimeCompareBytes(hash1, hash2) {
		t.Errorf("different tokens produced identical hash")
	}
}

func TestVerifyKeyRingHMAC_CurrentAndPrevious(t *testing.T) {
	ring := config.KeyRing{
		CurrentKeyID: 2,
		Keys: map[uint16][]byte{
			1: []byte("old-secret-key-1"),
			2: []byte("new-secret-key-2"),
		},
	}

	data := []byte("test-device-identifier-12345")

	// 1. Hash with old key
	oldHash := ComputeHMAC(data, ring.Keys[1])
	matched, kid, needsRotation := VerifyKeyRingHMAC(data, oldHash, ring)
	if !matched {
		t.Fatalf("expected match against old key")
	}
	if kid != 1 {
		t.Errorf("expected matched kid 1, got %d", kid)
	}
	if !needsRotation {
		t.Errorf("expected needsRotation to be true for old key match")
	}

	// 2. Hash with current key
	newHash, currentKID, err := ComputeKeyRingHMAC(data, ring)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if currentKID != 2 {
		t.Errorf("expected current kid 2, got %d", currentKID)
	}
	matched, kid, needsRotation = VerifyKeyRingHMAC(data, newHash, ring)
	if !matched || kid != 2 || needsRotation {
		t.Errorf("expected match with current key without rotation, got matched=%v, kid=%d, needsRotation=%v", matched, kid, needsRotation)
	}

	// 3. Unknown hash
	matched, _, _ = VerifyKeyRingHMAC(data, []byte("wrong-hash-0000000000000000000000"), ring)
	if matched {
		t.Errorf("expected no match for invalid hash")
	}
}
