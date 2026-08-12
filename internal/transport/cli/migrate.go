package cli

import (
	"errors"
	"fmt"

	"github.com/golang-migrate/migrate/v4"
	_ "github.com/golang-migrate/migrate/v4/database/postgres"
	_ "github.com/golang-migrate/migrate/v4/source/file"
	"github.com/spf13/cobra"
)

var (
	migrateDSN       string
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
	migrateCmd.PersistentFlags().StringVar(&migrateDSN, "dsn", "postgres://airlance:airlance@postgres:5432/airlance?sslmode=disable", "PostgreSQL DSN")
	migrateDownCmd.Flags().IntVar(&migrateDownSteps, "steps", 1, "number of migrations to roll back")

	migrateCmd.AddCommand(migrateUpCmd)
	migrateCmd.AddCommand(migrateDownCmd)
}

func getMigrator() (*migrate.Migrate, error) {
	m, err := migrate.New("file://migrations/postgres", migrateDSN)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize migrator: %w", err)
	}
	return m, nil
}

func runMigrateUp() error {
	m, err := getMigrator()
	if err != nil {
		return err
	}
	defer func() {
		_, _ = m.Close()
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
	m, err := getMigrator()
	if err != nil {
		return err
	}
	defer func() {
		_, _ = m.Close()
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
