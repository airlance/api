package nodeid

import (
	"crypto/rand"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func Load(filePath string) (string, error) {
	data, err := os.ReadFile(filePath)
	if err == nil {
		id := strings.TrimSpace(string(data))
		if id != "" {
			return id, nil
		}
	}
	if !os.IsNotExist(err) && err != nil {
		return "", fmt.Errorf("nodeid: read %s: %w", filePath, err)
	}

	var uuid [16]byte
	if _, err := rand.Read(uuid[:]); err != nil {
		return "", fmt.Errorf("nodeid: generate uuid: %w", err)
	}

	uuid[6] = (uuid[6] & 0x0f) | 0x40
	uuid[8] = (uuid[8] & 0x3f) | 0x80

	id := fmt.Sprintf("%08x-%04x-%04x-%04x-%12x",
		uuid[0:4], uuid[4:6], uuid[6:8], uuid[8:10], uuid[10:16])

	if err := os.MkdirAll(filepath.Dir(filePath), 0o755); err != nil {
		return "", fmt.Errorf("nodeid: mkdir %s: %w", filepath.Dir(filePath), err)
	}
	if err := os.WriteFile(filePath, []byte(id+"\n"), 0o644); err != nil {
		return "", fmt.Errorf("nodeid: write %s: %w", filePath, err)
	}

	return id, nil
}
