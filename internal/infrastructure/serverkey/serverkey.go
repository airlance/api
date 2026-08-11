package serverkey

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/airlance/api/internal/domain/serverkey"
)

const serverKeyFileVersion = 1

type ServerKeyPair struct {
	KeyID      string
	PrivateKey *ecdh.PrivateKey
}

func (k *ServerKeyPair) PublicKey() *ecdh.PublicKey {
	return k.PrivateKey.PublicKey()
}

type serverKeyFile struct {
	Version    int    `json:"version"`
	KeyID      string `json:"key_id"`
	PrivateKey string `json:"private_key_hex"`
	PublicKey  string `json:"public_key_hex"`
}

type FileServerKeyRepository struct {
	path string
}

var _ serverkey.Repository = (*FileServerKeyRepository)(nil)

func NewFileServerKeyRepository(path string) *FileServerKeyRepository {
	return &FileServerKeyRepository{path: path}
}

func (r *FileServerKeyRepository) LoadServerKeyPair() (publicKey, privateKey []byte, err error) {
	kp, err := LoadServerKeyPair(r.path)
	if err != nil {
		return nil, nil, err
	}
	return kp.PublicKey().Bytes(), kp.PrivateKey.Bytes(), nil
}

func GenerateServerKeyPair(keyID string) (*ServerKeyPair, error) {
	if keyID == "" {
		return nil, errors.New("serverkey: keyID must not be empty")
	}

	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("serverkey: failed to generate X25519 key: %w", err)
	}

	return &ServerKeyPair{KeyID: keyID, PrivateKey: priv}, nil
}

func SaveServerKeyPair(path string, kp *ServerKeyPair) error {
	file := serverKeyFile{
		Version:    serverKeyFileVersion,
		KeyID:      kp.KeyID,
		PrivateKey: hex.EncodeToString(kp.PrivateKey.Bytes()),
		PublicKey:  hex.EncodeToString(kp.PublicKey().Bytes()),
	}

	data, err := json.MarshalIndent(file, "", "  ")
	if err != nil {
		return fmt.Errorf("serverkey: failed to marshal key file: %w", err)
	}

	if err := os.WriteFile(path, data, 0o600); err != nil {
		return fmt.Errorf("serverkey: failed to write key file %s: %w", path, err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return fmt.Errorf("serverkey: failed to chmod key file %s: %w", path, err)
	}

	return nil
}

func LoadServerKeyPair(path string) (*ServerKeyPair, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("serverkey: failed to read key file %s: %w", path, err)
	}

	var file serverKeyFile
	if err := json.Unmarshal(data, &file); err != nil {
		return nil, fmt.Errorf("serverkey: failed to parse key file %s: %w", path, err)
	}

	if file.Version != serverKeyFileVersion {
		return nil, fmt.Errorf("serverkey: unsupported key file version %d (expected %d)", file.Version, serverKeyFileVersion)
	}
	if file.KeyID == "" {
		return nil, fmt.Errorf("serverkey: key file %s missing key_id", path)
	}

	privBytes, err := hex.DecodeString(file.PrivateKey)
	if err != nil {
		return nil, fmt.Errorf("serverkey: invalid private_key_hex in %s: %w", path, err)
	}

	priv, err := ecdh.X25519().NewPrivateKey(privBytes)
	if err != nil {
		return nil, fmt.Errorf("serverkey: invalid X25519 private key in %s: %w", path, err)
	}

	kp := &ServerKeyPair{KeyID: file.KeyID, PrivateKey: priv}

	if got := hex.EncodeToString(kp.PublicKey().Bytes()); got != file.PublicKey {
		return nil, fmt.Errorf("serverkey: public_key_hex in %s does not match private key (file corrupted?)", path)
	}

	return kp, nil
}
