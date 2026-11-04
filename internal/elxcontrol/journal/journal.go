// Package journal stores Control commands until the node confirms durable application.
package journal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"math"
)

var (
	ErrInvalid  = errors.New("invalid operation")
	ErrConflict = errors.New("operation ID reused with different content")
	ErrRevision = errors.New("unexpected target revision")
	ErrPending  = errors.New("target already has a pending operation")
	ErrReceipt  = errors.New("receipt does not match a recorded operation")
)

// Target identifies a resource on an authenticated node.
type Target struct {
	NodeID     string
	ResourceID string
}

type Command struct {
	ID               string
	ExpectedRevision int64
	Payload          []byte
}

// Enqueue records the command before delivery. Retry ambiguous commits with
// the original ID and payload. Revisions advance only after application.
func Enqueue(ctx context.Context, db *sql.DB, target Target, cmd Command) (int64, error) {
	if cmd.ExpectedRevision < 0 || cmd.ExpectedRevision == math.MaxInt64 ||
		len(cmd.Payload) == 0 || len(cmd.Payload) > 256*1024 {
		return 0, ErrInvalid
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO elx_operation_targets(node_id, resource_id)
		VALUES ($1,$2) ON CONFLICT DO NOTHING`, target.NodeID, target.ResourceID)
	if err != nil {
		return 0, err
	}
	var current int64
	err = tx.QueryRowContext(ctx, `SELECT revision FROM elx_operation_targets
		WHERE node_id=$1 AND resource_id=$2 FOR UPDATE`, target.NodeID, target.ResourceID).Scan(&current)
	if err != nil {
		return 0, err
	}
	var existing int64
	var payload []byte
	next := cmd.ExpectedRevision + 1
	err = tx.QueryRowContext(ctx, `SELECT revision,payload FROM elx_operations
		WHERE node_id=$1 AND resource_id=$2 AND operation_id=$3`,
		target.NodeID, target.ResourceID, cmd.ID).Scan(&existing, &payload)
	switch {
	case err == nil:
		if existing != next || !bytes.Equal(payload, cmd.Payload) {
			return 0, ErrConflict
		}
		return existing, tx.Commit()
	case !errors.Is(err, sql.ErrNoRows):
		return 0, err
	case current != cmd.ExpectedRevision:
		return 0, ErrRevision
	}
	var pending bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM elx_operations
		WHERE node_id=$1 AND resource_id=$2 AND applied_at IS NULL)`,
		target.NodeID, target.ResourceID).Scan(&pending)
	if err != nil {
		return 0, err
	}
	if pending {
		return 0, ErrPending
	}
	hash := sha256.Sum256(cmd.Payload)
	_, err = tx.ExecContext(ctx, `INSERT INTO elx_operations
		(node_id,resource_id,operation_id,revision,payload,payload_hash)
		VALUES ($1,$2,$3,$4,$5,$6)`, target.NodeID, target.ResourceID, cmd.ID, next, cmd.Payload, hash[:])
	if err != nil {
		return 0, err
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return next, nil
}

// ConfirmApplied persists a receipt after the caller validates node identity,
// authority epoch, executor incarnation and durable application evidence.
func ConfirmApplied(ctx context.Context, db *sql.DB, target Target, id string, revision int64, hash [32]byte) error {
	if revision <= 0 {
		return ErrReceipt
	}
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var current int64
	err = tx.QueryRowContext(ctx, `SELECT revision FROM elx_operation_targets
		WHERE node_id=$1 AND resource_id=$2 FOR UPDATE`, target.NodeID, target.ResourceID).Scan(&current)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrReceipt
	}
	if err != nil {
		return err
	}
	var applied bool
	err = tx.QueryRowContext(ctx, `SELECT applied_at IS NOT NULL FROM elx_operations
		WHERE node_id=$1 AND resource_id=$2 AND operation_id=$3 AND revision=$4 AND payload_hash=$5`,
		target.NodeID, target.ResourceID, id, revision, hash[:]).Scan(&applied)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrReceipt
	}
	if err != nil {
		return err
	}
	if applied {
		return tx.Commit()
	}
	if current != revision-1 {
		return ErrRevision
	}
	_, err = tx.ExecContext(ctx, `UPDATE elx_operations SET applied_at=now()
		WHERE node_id=$1 AND resource_id=$2 AND operation_id=$3`, target.NodeID, target.ResourceID, id)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE elx_operation_targets SET revision=$3
		WHERE node_id=$1 AND resource_id=$2`, target.NodeID, target.ResourceID, revision)
	if err != nil {
		return err
	}
	return tx.Commit()
}

// Pending returns the command to redeliver after a reconnect. Delivery alone
// never clears the row. The receiver must deduplicate by operation ID.
func Pending(ctx context.Context, db *sql.DB, target Target) (Command, error) {
	var cmd Command
	err := db.QueryRowContext(ctx, `SELECT operation_id, revision-1, payload
		FROM elx_operations WHERE node_id=$1 AND resource_id=$2 AND applied_at IS NULL`,
		target.NodeID, target.ResourceID).Scan(&cmd.ID, &cmd.ExpectedRevision, &cmd.Payload)
	return cmd, err
}

// Lookup finds the original command even after its receipt was committed.
func Lookup(ctx context.Context, db *sql.DB, target Target, operationID string) (Command, error) {
	cmd := Command{ID: operationID}
	err := db.QueryRowContext(ctx, `SELECT revision-1, payload FROM elx_operations
		WHERE node_id=$1 AND resource_id=$2 AND operation_id=$3`,
		target.NodeID, target.ResourceID, operationID).Scan(&cmd.ExpectedRevision, &cmd.Payload)
	return cmd, err
}
