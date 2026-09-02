package wireauth

import (
	"crypto/rand"
	"crypto/rsa"
	"testing"

	"github.com/resoul/wireauth/v2"
)

func TestWireauthV2_EncryptionDecryptionContract(t *testing.T) {
	key := make([]byte, 32)
	_, _ = rand.Read(key)

	plaintext := []byte("Hello FlatBuffers over Wireauth v2 Encrypted Channel!")
	seq := uint64(1)

	// 1. Encrypt
	ciphertext, err := wireauth.EncryptAESGCM(key, plaintext, seq)
	if err != nil {
		t.Fatalf("unexpected encryption error: %v", err)
	}

	// 2. Decrypt with correct key and extract sequence
	decrypted, decryptedSeq, err := wireauth.DecryptAESGCM(key, ciphertext)
	if err != nil {
		t.Fatalf("unexpected decryption error: %v", err)
	}

	if string(decrypted) != string(plaintext) {
		t.Errorf("expected plaintext %s, got %s", string(plaintext), string(decrypted))
	}
	if decryptedSeq != seq {
		t.Errorf("expected sequence %d, got %d", seq, decryptedSeq)
	}

	// 3. Decrypt with corrupted key
	wrongKey := make([]byte, 32)
	_, _, err = wireauth.DecryptAESGCM(wrongKey, ciphertext)
	if err == nil {
		t.Errorf("expected error when decrypting with wrong key")
	}

	// 4. Decrypt with truncated/corrupted ciphertext
	_, _, err = wireauth.DecryptAESGCM(key, ciphertext[:len(ciphertext)-5])
	if err == nil {
		t.Errorf("expected error when decrypting corrupted ciphertext")
	}
}

func TestWireauthV2_ServerInitialization(t *testing.T) {
	privKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}

	srv := wireauth.NewServer(privKey)
	if srv == nil {
		t.Fatalf("expected non-nil wireauth server")
	}
}
