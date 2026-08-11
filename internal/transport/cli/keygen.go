package cli

import (
	"errors"
	"fmt"
	"os"

	"github.com/airlance/api/internal/infrastructure/serverkey"
	"github.com/spf13/cobra"
)

var (
	keygenOut   string
	keygenKeyID string
	keygenForce bool
)

var keygenCmd = &cobra.Command{
	Use:   "keygen",
	Short: "Generate static X25519 keypair for Noise IK server identity",
	RunE: func(cmd *cobra.Command, args []string) error {
		if keygenKeyID == "" {
			return errors.New("error: --key-id is required (e.g. --key-id=v1)")
		}

		if !keygenForce {
			if _, err := os.Stat(keygenOut); err == nil {
				return fmt.Errorf("error: key file %s already exists, use --force to overwrite", keygenOut)
			}
		}

		kp, err := serverkey.GenerateServerKeyPair(keygenKeyID)
		if err != nil {
			return fmt.Errorf("keygen: failed to generate keypair: %w", err)
		}

		if err := serverkey.SaveServerKeyPair(keygenOut, kp); err != nil {
			return fmt.Errorf("keygen: failed to save keypair: %w", err)
		}

		fmt.Printf("Generated keypair, key_id=%s\n", kp.KeyID)
		fmt.Printf("Saved to %s (permissions 0600)\n", keygenOut)
		fmt.Printf("Public key (hex): %x\n", kp.PublicKey().Bytes())
		return nil
	},
}

func init() {
	keygenCmd.Flags().StringVar(&keygenOut, "out", "server-key.json", "output path for server keypair")
	keygenCmd.Flags().StringVar(&keygenKeyID, "key-id", "", "key identifier (e.g. 'v1', required)")
	keygenCmd.Flags().BoolVar(&keygenForce, "force", false, "force overwrite existing key file")
}
