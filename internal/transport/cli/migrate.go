package cli

import (
	"errors"
	"fmt"
	"log"

	"github.com/airlance/api/internal/config"
	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/spf13/cobra"
)

var (
	migrateDownSteps int
)

var migrateCmd = &cobra.Command{
	Use:   "migrate",
	Short: "PostgreSQL database migrations management",
}

var migrateUpCmd = &cobra.Command{
	Use:   "up",
	Short: "Apply all PostgreSQL database migrations",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runMigrateUp()
	},
}

var migrateDownCmd = &cobra.Command{
	Use:   "down",
	Short: "Rollback PostgreSQL database migrations",
	RunE: func(cmd *cobra.Command, args []string) error {
		return runMigrateDown(migrateDownSteps)
	},
}

func init() {
	migrateDownCmd.Flags().IntVar(&migrateDownSteps, "steps", 1, "number of migrations to roll back")

	migrateCmd.AddCommand(migrateUpCmd)
	migrateCmd.AddCommand(migrateDownCmd)
}

func getMigrator(cfg *config.Config) (*migrate.Migrate, error) {
	m, err := migrate.New("file://migrations/postgres", cfg.Database.DSN)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize migrator: %w", err)
	}
	return m, nil
}

func runMigrateUp() error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	m, err := getMigrator(cfg)
	if err != nil {
		return err
	}
	defer func() {
		if err, _ := m.Close(); err != nil {
			log.Printf("Failed to close migrator: %v", err)
		}
	}()

	if err := m.Up(); err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			fmt.Println("No migrations to apply.")
			return nil
		}
		return fmt.Errorf("failed to apply migrations: %w", err)
	}
	fmt.Println("Migrations applied successfully!")
	return nil
}

func runMigrateDown(steps int) error {
	cfg, err := config.Load()
	if err != nil {
		return fmt.Errorf("failed to load config: %w", err)
	}
	m, err := getMigrator(cfg)
	if err != nil {
		return err
	}
	defer func() {
		if err, _ := m.Close(); err != nil {
			log.Printf("Failed to close migrator: %v", err)
		}
	}()

	if err := m.Steps(-steps); err != nil {
		if errors.Is(err, migrate.ErrNoChange) {
			fmt.Println("No migrations to rollback.")
			return nil
		}
		return fmt.Errorf("failed to rollback migrations: %w", err)
	}
	fmt.Printf("Rolled back %d migration(s) successfully!\n", steps)
	return nil
}
