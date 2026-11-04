package journal

import (
	"context"
	"crypto/sha256"
	"database/sql"
	_ "embed"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
)

//go:embed 001_operations.sql
var schema string

// Migrate installs the journal schema in the Control database. The database
// role must have DDL privileges in its configured schema.
func Migrate(ctx context.Context, db *sql.DB) error {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, "SELECT pg_advisory_xact_lock(391762480121001)"); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `CREATE TABLE IF NOT EXISTS elx_journal_migrations (
		version integer PRIMARY KEY, checksum text NOT NULL
	)`); err != nil {
		return err
	}
	sum := sha256.Sum256([]byte(schema))
	checksum := hex.EncodeToString(sum[:])
	var previous string
	err = tx.QueryRowContext(ctx, "SELECT checksum FROM elx_journal_migrations WHERE version=1").Scan(&previous)
	switch {
	case err == nil:
		if previous != checksum {
			return errors.New("journal migration 001 checksum mismatch")
		}
	case errors.Is(err, sql.ErrNoRows):
		for _, stmt := range strings.Split(schema, ";") {
			if strings.TrimSpace(stmt) == "" {
				continue
			}
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				return fmt.Errorf("journal migration 001: %w", err)
			}
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO elx_journal_migrations VALUES (1,$1)", checksum); err != nil {
			return err
		}
	default:
		return err
	}
	return tx.Commit()
}
