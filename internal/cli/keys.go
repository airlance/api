package cli

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/spf13/cobra"
)

func newKeysCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "keys",
		Short: "Generate signing/HMAC key material for local and production use",
	}

	cmd.AddCommand(
		newKeysHMACCmd(),
		newKeysJWTCmd(),
		newKeysWireauthCmd(),
		newKeysAllCmd(),
	)

	return cmd
}

func newKeysHMACCmd() *cobra.Command {
	var id uint16

	cmd := &cobra.Command{
		Use:   "hmac",
		Short: "Generate one DEVICE_HMAC_KEYS / AUDIT_HMAC_KEYS / OTP_HMAC_KEYS entry",
		Long: "Generates a random 32-byte HMAC key, hex-encoded, in the " +
			"\"id:secret\" form parsed by config.parseHMACKeyRing. Run it " +
			"for a fresh deployment: for DEVICE_HMAC_KEYS, " +
			"AUDIT_HMAC_KEYS, and OTP_HMAC_KEYS. Never reuse the same key for multiple purposes.",
		RunE: func(cmd *cobra.Command, args []string) error {
			entry, err := generateHMACEntry(id)
			if err != nil {
				return err
			}
			fmt.Println(entry)
			return nil
		},
	}

	cmd.Flags().Uint16Var(&id, "id", 1, "Key ID to prefix the entry with (bump on rotation)")
	return cmd
}

func newKeysJWTCmd() *cobra.Command {
	var kid string

	cmd := &cobra.Command{
		Use:   "jwt",
		Short: "Generate one JWT_ED25519_KEYS entry",
		Long: "Generates an Ed25519 seed in the \"kid:base64_seed\" form " +
			"parsed by config.parseEd25519KeyRing, and prints the matching " +
			"public key for reference. Set JWT_CURRENT_KID to the kid you " +
			"keep as current; keep retired kids in JWT_ED25519_KEYS until " +
			"no issued token can still reference them.",
		RunE: func(cmd *cobra.Command, args []string) error {
			entry, pub, err := generateJWTEntry(kid)
			if err != nil {
				return err
			}
			fmt.Println(entry)
			fmt.Fprintf(os.Stderr, "# public key (informational only, not part of the env value): %s\n",
				base64.StdEncoding.EncodeToString(pub))
			return nil
		},
	}

	cmd.Flags().StringVar(&kid, "kid", "key-1", "Key ID to prefix the entry with (bump on rotation)")
	return cmd
}

func newKeysWireauthCmd() *cobra.Command {
	var bits int
	var out string

	cmd := &cobra.Command{
		Use:   "wireauth",
		Short: "Generate an RSA private key for WIREAUTH_RSA_KEY_PATH",
		Long: "Generates a PKCS#8 PEM RSA private key for the wireauth v2 " +
			"handshake and writes it with 0600 permissions. Point " +
			"WIREAUTH_RSA_KEY_PATH at the resulting file, or paste its " +
			"contents into WIREAUTH_RSA_KEY_PEM for environments without a " +
			"writable filesystem (e.g. a secret manager).",
		RunE: func(cmd *cobra.Command, args []string) error {
			if bits < 2048 {
				return fmt.Errorf("keys wireauth: --bits must be >= 2048 (config.go rejects smaller keys)")
			}
			if err := generateWireauthKeyFile(bits, out); err != nil {
				return err
			}
			fmt.Fprintf(os.Stderr, "wrote %d-bit RSA private key to %s (mode 0600)\n", bits, out)
			return nil
		},
	}

	cmd.Flags().IntVar(&bits, "bits", 3072, "RSA key size in bits (minimum 2048)")
	cmd.Flags().StringVar(&out, "out", "wireauth_private_key.pem", "Output PEM file path")
	return cmd
}

func newKeysAllCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "all",
		Short: "Generate a full, ready-to-paste set of secrets for a fresh environment",
		Long: "Convenience wrapper around hmac/jwt/wireauth for bootstrapping " +
			"a new environment (local, staging, or production). Every value " +
			"is freshly random on each run - it does not read or modify any " +
			"existing configuration. Treat the output as a secret: pipe it " +
			"straight into your secret manager rather than committing it.",
		RunE: func(cmd *cobra.Command, args []string) error {
			deviceEntry, err := generateHMACEntry(1)
			if err != nil {
				return fmt.Errorf("device HMAC key: %w", err)
			}
			auditEntry, err := generateHMACEntry(1)
			if err != nil {
				return fmt.Errorf("audit HMAC key: %w", err)
			}
			otpEntry, err := generateHMACEntry(1)
			if err != nil {
				return fmt.Errorf("OTP HMAC key: %w", err)
			}
			jwtEntry, _, err := generateJWTEntry("key-1")
			if err != nil {
				return fmt.Errorf("JWT key: %w", err)
			}
			const wireauthOut = "wireauth_private_key.pem"
			if err := generateWireauthKeyFile(3072, wireauthOut); err != nil {
				return fmt.Errorf("wireauth key: %w", err)
			}

			fmt.Println("# Paste these into your secret manager or local .env.")
			fmt.Println("# Each run of `keys all` produces different values; do not reuse")
			fmt.Println("# the ones printed here as an example.")
			fmt.Printf("DEVICE_HMAC_KEYS=%s\n", deviceEntry)
			fmt.Println("DEVICE_HMAC_CURRENT_KEY_ID=1")
			fmt.Printf("AUDIT_HMAC_KEYS=%s\n", auditEntry)
			fmt.Println("AUDIT_HMAC_CURRENT_KEY_ID=1")
			fmt.Printf("OTP_HMAC_KEYS=%s\n", otpEntry)
			fmt.Println("OTP_HMAC_CURRENT_KEY_ID=1")
			fmt.Printf("JWT_ED25519_KEYS=%s\n", jwtEntry)
			fmt.Println("JWT_CURRENT_KID=key-1")
			fmt.Printf("WIREAUTH_RSA_KEY_PATH=%s\n", wireauthOut)
			return nil
		},
	}
}

func generateHMACEntry(id uint16) (string, error) {
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("keys hmac: random read failed: %w", err)
	}
	return fmt.Sprintf("%d:%s", id, hex.EncodeToString(secret)), nil
}

func generateJWTEntry(kid string) (entry string, pub ed25519.PublicKey, err error) {
	if kid == "" {
		return "", nil, fmt.Errorf("keys jwt: --kid must not be empty")
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return "", nil, fmt.Errorf("keys jwt: generate key failed: %w", err)
	}
	seed := priv.Seed()
	entry = fmt.Sprintf("%s:%s", kid, base64.StdEncoding.EncodeToString(seed))
	return entry, pub, nil
}

func generateWireauthKeyFile(bits int, out string) error {
	key, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		return fmt.Errorf("keys wireauth: generate key failed: %w", err)
	}
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return fmt.Errorf("keys wireauth: marshal key failed: %w", err)
	}
	block := &pem.Block{Type: "PRIVATE KEY", Bytes: der}

	f, err := os.OpenFile(out, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("keys wireauth: open %s failed: %w", out, err)
	}
	defer func() { _ = f.Close() }()

	if err := pem.Encode(f, block); err != nil {
		return fmt.Errorf("keys wireauth: write %s failed: %w", out, err)
	}
	return nil
}
