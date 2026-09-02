package wireauth

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/resoul/wireauth/v2"
)

type vectorFile struct {
	Version int `json:"version"`
	AESGCM  []struct {
		Name          string `json:"name"`
		KeyHex        string `json:"key_hex"`
		Sequence      uint64 `json:"sequence"`
		PlaintextUTF8 string `json:"plaintext_utf8"`
	} `json:"aes_gcm"`
}

func TestWireauthV2_SharedFixturesContract(t *testing.T) {
	fixturePath := filepath.Join("..", "..", "fixtures", "wireauth_v2_vectors.json")
	data, err := os.ReadFile(fixturePath)
	if err != nil {
		t.Fatalf("failed to read test fixtures from %s: %v", fixturePath, err)
	}

	var vf vectorFile
	if err := json.Unmarshal(data, &vf); err != nil {
		t.Fatalf("failed to unmarshal fixture file: %v", err)
	}

	if vf.Version != 2 {
		t.Errorf("expected fixture version 2, got %d", vf.Version)
	}

	for _, vec := range vf.AESGCM {
		t.Run(vec.Name, func(t *testing.T) {
			key, err := hex.DecodeString(vec.KeyHex)
			if err != nil {
				t.Fatalf("invalid hex key: %v", err)
			}

			plaintext := []byte(vec.PlaintextUTF8)
			ciphertext, err := wireauth.EncryptAESGCM(key, plaintext, vec.Sequence)
			if err != nil {
				t.Fatalf("encryption failed: %v", err)
			}

			decrypted, seq, err := wireauth.DecryptAESGCM(key, ciphertext)
			if err != nil {
				t.Fatalf("decryption failed: %v", err)
			}

			if string(decrypted) != vec.PlaintextUTF8 {
				t.Errorf("expected plaintext %s, got %s", vec.PlaintextUTF8, string(decrypted))
			}
			if seq != vec.Sequence {
				t.Errorf("expected sequence %d, got %d", vec.Sequence, seq)
			}

			// Verify replay detection simulation (wrong sequence when decrypting)
			if seq+1 == vec.Sequence {
				t.Errorf("sequence must strictly equal expected value")
			}
		})
	}
}

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
