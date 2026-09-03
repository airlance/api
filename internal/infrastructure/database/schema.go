package database

import (
	"errors"
	"fmt"
	"path/filepath"
	"strings"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	_ "github.com/golang-migrate/migrate/v4/source/file"
)

func GetCurrentSchemaVersion(dsn, dir string) (uint, bool, error) {
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return 0, false, err
	}

	migrateDSN := dsn
	if strings.HasPrefix(migrateDSN, "postgres://") {
		migrateDSN = "pgx5://" + strings.TrimPrefix(migrateDSN, "postgres://")
	} else if strings.HasPrefix(migrateDSN, "postgresql://") {
		migrateDSN = "pgx5://" + strings.TrimPrefix(migrateDSN, "postgresql://")
	}

	m, err := migrate.New(fmt.Sprintf("file://%s", absDir), migrateDSN)
	if err != nil {
		return 0, false, err
	}
	defer func() { _, _ = m.Close() }()

	v, dirty, err := m.Version()
	if err != nil {
		if errors.Is(err, migrate.ErrNilVersion) {
			return 0, false, nil
		}
		return 0, false, err
	}
	return v, dirty, nil
}
