package cli

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/pgx/v5"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/spf13/cobra"

	"airlance.org/api/internal/config"
)

var (
	migrationsDir = "migrations"
)

func newMigrateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "migrate",
		Short: "Database migration commands",
	}

	cmd.PersistentFlags().StringVar(&migrationsDir, "dir", "migrations", "Path to migrations directory")

	cmd.AddCommand(
		newMigrateUpCmd(),
		newMigrateDownCmd(),
		newMigrateResetCmd(),
		newMigrateVersionCmd(),
		newMigrateCreateCmd(),
	)

	return cmd
}

func getMigrateInstance(dsn string) (*migrate.Migrate, error) {
	absDir, err := filepath.Abs(migrationsDir)
	if err != nil {
		return nil, fmt.Errorf("invalid migrations dir: %w", err)
	}

	if _, err := os.Stat(absDir); os.IsNotExist(err) {
		if err := os.MkdirAll(absDir, 0755); err != nil {
			return nil, fmt.Errorf("failed to create migrations dir: %w", err)
		}
	}

	m, err := migrate.New(fmt.Sprintf("file://%s", absDir), dsn)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize migrate: %w", err)
	}
	return m, nil
}

func newMigrateUpCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "up",
		Short: "Apply all available migrations",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.LoadFromEnv()
			if err != nil {
				return err
			}

			m, err := getMigrateInstance(cfg.DatabaseDSN)
			if err != nil {
				return err
			}
			defer func() { _, _ = m.Close() }()

			if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
				return fmt.Errorf("migration up failed: %w", err)
			}

			v, dirty, _ := m.Version()
			fmt.Printf("Migrations applied successfully. Current version: %d (dirty: %v)\n", v, dirty)
			return nil
		},
	}
}

func newMigrateDownCmd() *cobra.Command {
	var steps int
	cmd := &cobra.Command{
		Use:   "down",
		Short: "Roll back migrations",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.LoadFromEnv()
			if err != nil {
				return err
			}

			m, err := getMigrateInstance(cfg.DatabaseDSN)
			if err != nil {
				return err
			}
			defer func() { _, _ = m.Close() }()

			if steps <= 0 {
				steps = 1
			}

			if err := m.Steps(-steps); err != nil && !errors.Is(err, migrate.ErrNoChange) {
				return fmt.Errorf("migration down failed: %w", err)
			}

			v, dirty, _ := m.Version()
			fmt.Printf("Migrations rolled back by %d step(s). Current version: %d (dirty: %v)\n", steps, v, dirty)
			return nil
		},
	}
	cmd.Flags().IntVar(&steps, "steps", 1, "Number of migrations to roll back")
	return cmd
}

func newMigrateResetCmd() *cobra.Command {
	var force bool
	cmd := &cobra.Command{
		Use:   "reset",
		Short: "Drop all tables and re-apply all migrations",
		RunE: func(cmd *cobra.Command, args []string) error {
			if !force {
				return errors.New("reset requires --force flag")
			}

			cfg, err := config.LoadFromEnv()
			if err != nil {
				return err
			}

			m, err := getMigrateInstance(cfg.DatabaseDSN)
			if err != nil {
				return err
			}
			defer func() { _, _ = m.Close() }()

			if err := m.Drop(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
				return fmt.Errorf("migration drop failed: %w", err)
			}

			if err := m.Up(); err != nil && !errors.Is(err, migrate.ErrNoChange) {
				return fmt.Errorf("migration up after reset failed: %w", err)
			}

			v, dirty, _ := m.Version()
			fmt.Printf("Database reset and migrated to version: %d (dirty: %v)\n", v, dirty)
			return nil
		},
	}
	cmd.Flags().BoolVar(&force, "force", false, "Force database reset")
	return cmd
}

func newMigrateVersionCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print current migration version",
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg, err := config.LoadFromEnv()
			if err != nil {
				return err
			}

			m, err := getMigrateInstance(cfg.DatabaseDSN)
			if err != nil {
				return err
			}
			defer func() { _, _ = m.Close() }()

			v, dirty, err := m.Version()
			if err != nil {
				if errors.Is(err, migrate.ErrNilVersion) {
					fmt.Println("No migrations applied yet (version 0)")
					return nil
				}
				return fmt.Errorf("failed to get migration version: %w", err)
			}

			fmt.Printf("Current migration version: %d (dirty: %v)\n", v, dirty)
			return nil
		},
	}
}

func newMigrateCreateCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "create <name>",
		Short: "Create a new migration file pair",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]
			absDir, err := filepath.Abs(migrationsDir)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(absDir, 0755); err != nil {
				return err
			}

			nextNum := getNextMigrationNumber(absDir)
			upFile := filepath.Join(absDir, fmt.Sprintf("%06d_%s.up.sql", nextNum, name))
			downFile := filepath.Join(absDir, fmt.Sprintf("%06d_%s.down.sql", nextNum, name))

			if err := os.WriteFile(upFile, []byte("-- Up migration\n"), 0644); err != nil {
				return err
			}
			if err := os.WriteFile(downFile, []byte("-- Down migration\n"), 0644); err != nil {
				return err
			}

			fmt.Printf("Created migration files:\n  %s\n  %s\n", upFile, downFile)
			return nil
		},
	}
}

func getNextMigrationNumber(dir string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 1
	}

	maxSeq := 0
	for _, entry := range entries {
		name := entry.Name()
		if len(name) >= 6 {
			if seq, err := strconv.Atoi(name[:6]); err == nil {
				if seq > maxSeq {
					maxSeq = seq
				}
			}
		}
	}
	return maxSeq + 1
}
