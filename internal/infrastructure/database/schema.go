package database

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

// GetCurrentSchemaVersion inspects the PostgreSQL migration version.
func GetCurrentSchemaVersion(dsn, dir string) (uint, bool, error) {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return 0, false, err
	}
	m, err := migrate.New(fmt.Sprintf("file://%s", absDir), dsn)
	if err != nil {
		return 0, false, err
	}
	defer m.Close()

	v, dirty, err := m.Version()
	if err != nil {
		if errors.Is(err, migrate.ErrNilVersion) {
			return 0, false, nil
		}
		return 0, false, err
	}
	return v, dirty, nil
}
