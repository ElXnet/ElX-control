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

//go:embed 002_sessions.sql
var sessionSchema string

//go:embed 003_device_proof.sql
var deviceProofSchema string

//go:embed 004_accounting.sql
var accountingSchema string

//go:embed 005_rate_grants.sql
var rateGrantSchema string

//go:embed 006_session_fences.sql
var sessionFenceSchema string

//go:embed 007_core_identities.sql
var coreIdentitySchema string

//go:embed 008_accounting_assignments.sql
var accountingAssignmentSchema string

//go:embed 009_period_schedules.sql
var periodScheduleSchema string

//go:embed 010_remote_usage_challenges.sql
var remoteUsageChallengeSchema string

//go:embed 011_session_profile_binding.sql
var sessionProfileSchema string

//go:embed 012_lk.sql
var lkSchema string

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
	for i, ddl := range []string{schema, sessionSchema, deviceProofSchema, accountingSchema, rateGrantSchema, sessionFenceSchema, coreIdentitySchema, accountingAssignmentSchema, periodScheduleSchema, remoteUsageChallengeSchema, sessionProfileSchema, lkSchema} {
		if err := applyMigration(ctx, tx, i+1, ddl); err != nil {
			return err
		}
	}
	return tx.Commit()
}

func applyMigration(ctx context.Context, tx *sql.Tx, version int, ddl string) error {
	sum := sha256.Sum256([]byte(ddl))
	checksum := hex.EncodeToString(sum[:])
	var previous string
	err := tx.QueryRowContext(ctx, "SELECT checksum FROM elx_journal_migrations WHERE version=$1", version).Scan(&previous)
	switch {
	case err == nil:
		if previous != checksum {
			return fmt.Errorf("Control migration %03d checksum mismatch", version)
		}
	case errors.Is(err, sql.ErrNoRows):
		for _, stmt := range splitSQLStatements(ddl) {
			if strings.TrimSpace(stmt) == "" {
				continue
			}
			if _, err := tx.ExecContext(ctx, stmt); err != nil {
				return fmt.Errorf("Control migration %03d: %w", version, err)
			}
		}
		if _, err := tx.ExecContext(ctx, "INSERT INTO elx_journal_migrations VALUES ($1,$2)", version, checksum); err != nil {
			return err
		}
	default:
		return err
	}
	return nil
}

// splitSQLStatements handles SQL comments, strings, identifiers and dollar
// quotes so a semicolon in a comment or a future procedural migration cannot
// become an executable statement. Migrations remain checksummed verbatim.
func splitSQLStatements(src string) []string {
	var statements []string
	var statement strings.Builder
	var dollarTag string
	state := byte(0) // normal, single quote, double quote, line/block comment, dollar quote.
	for i := 0; i < len(src); {
		c := src[i]
		hasNext := i+1 < len(src)
		switch state {
		case 0:
			switch {
			case c == '-' && hasNext && src[i+1] == '-':
				state = 'l'; i += 2
			case c == '/' && hasNext && src[i+1] == '*':
				state = 'b'; i += 2
			case c == '\'':
				state = 's'; statement.WriteByte(c); i++
			case c == '"':
				state = 'q'; statement.WriteByte(c); i++
			case c == '$':
				j := i+1
				for j < len(src) && (src[j] == '_' || src[j] >= '0' && src[j] <= '9' ||
					src[j] >= 'A' && src[j] <= 'Z' || src[j] >= 'a' && src[j] <= 'z') {
					j++
				}
				if j < len(src) && src[j] == '$' {
					dollarTag = src[i:j+1]
					statement.WriteString(dollarTag)
					i = j+1
					state = 'd'
				} else {
					statement.WriteByte(c); i++
				}
			case c == ';':
				if strings.TrimSpace(statement.String()) != "" {
					statements = append(statements, statement.String())
				}
				statement.Reset()
				i++
			default:
				statement.WriteByte(c); i++
			}
		case 'l':
			if c == '\n' {
				state = 0
				statement.WriteByte('\n')
			}
			i++
		case 'b':
			if c == '*' && hasNext && src[i+1] == '/' {
				state = 0
				i += 2
				statement.WriteByte(' ')
			} else {
				if c == '\n' { statement.WriteByte('\n') }
				i++
			}
		case 's', 'q':
			statement.WriteByte(c)
			i++
			var quote byte = '\''
			if state == 'q' { quote = '"' }
			if c == quote {
				if i < len(src) && src[i] == quote {
					statement.WriteByte(src[i]); i++
				} else {
					state = 0
				}
			}
		case 'd':
			if strings.HasPrefix(src[i:], dollarTag) {
				statement.WriteString(dollarTag)
				i += len(dollarTag)
				state = 0
			} else {
				statement.WriteByte(c)
				i++
			}
		}
	}
	if strings.TrimSpace(statement.String()) != "" {
		statements = append(statements, statement.String())
	}
	return statements
}
