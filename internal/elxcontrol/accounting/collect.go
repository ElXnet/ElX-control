package accounting

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"

	"github.com/google/uuid"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/corepolicy"
)

// Assignment is provisioned by Control. Values arriving from an end-user or
// VPN transport must never be treated as authoritative assignments.
type Assignment struct {
	NodeID       uuid.UUID
	ExecutorID   uuid.UUID
	Incarnation  uuid.UUID
	AccountingID uuid.UUID
	Generation   int64
	PeriodID     uuid.UUID
}

// UsageReader verifies ElXray's signature with the pinned Ed25519 public key
// and a fresh challenge. corepolicy.Client implements this interface.
type UsageReader interface {
	ReadUsage(context.Context, string, ed25519.PublicKey) (corepolicy.Usage, error)
}

func validAssignment(authenticatedNode uuid.UUID, a Assignment) bool {
	return authenticatedNode != uuid.Nil && authenticatedNode == a.NodeID &&
		a.ExecutorID != uuid.Nil && a.Incarnation != uuid.Nil &&
		a.AccountingID != uuid.Nil && a.Generation > 0
}

// Collect accepts an explicitly provisioned accounting period. For scheduled
// FUP periods, prefer CollectCurrent so a rollover cannot invalidate a stale
// caller-supplied period ID between selection and sample ingestion.
func Collect(ctx context.Context, db *sql.DB, authenticatedNode uuid.UUID, a Assignment, reader UsageReader) (Receipt, error) {
	if db == nil || reader == nil || !validAssignment(authenticatedNode, a) || a.PeriodID == uuid.Nil {
		return Receipt{}, ErrSample
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return Receipt{}, err
	}
	defer tx.Rollback()
	out, err := collectInTx(ctx, tx, authenticatedNode, a, reader)
	if err != nil {
		return Receipt{}, err
	}
	if err := tx.Commit(); err != nil {
		return Receipt{}, err
	}
	return out, nil
}

// CollectCurrent resolves a schedule's current open period INSIDE the sample
// transaction. A schedule SHARE lock serializes its rollover with signed
// readback and high-watermark commit. No client can choose a past period.
// authenticatedNode must be supplied by verified mTLS or a trusted supervisor.
func CollectCurrent(ctx context.Context, db *sql.DB, authenticatedNode uuid.UUID, schedule uuid.UUID,
	a Assignment, reader UsageReader) (Receipt, error) {
	if db == nil || reader == nil || schedule == uuid.Nil ||
		!validAssignment(authenticatedNode, a) || a.PeriodID != uuid.Nil {
		return Receipt{}, ErrSample
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return Receipt{}, err
	}
	defer tx.Rollback()
	err = tx.QueryRowContext(ctx, `SELECT s.current_period_id
		FROM elx_period_schedules s JOIN elx_usage_periods p ON p.id=s.current_period_id
		WHERE s.id=$1 AND p.starts_at<=clock_timestamp()
			AND p.ends_at>clock_timestamp()
		FOR SHARE OF s`, schedule).Scan(&a.PeriodID)
	if errors.Is(err, sql.ErrNoRows) {
		return Receipt{}, ErrStream
	}
	if err != nil {
		return Receipt{}, err
	}
	out, err := collectInTx(ctx, tx, authenticatedNode, a, reader)
	if err != nil {
		return Receipt{}, err
	}
	if err := tx.Commit(); err != nil {
		return Receipt{}, err
	}
	return out, nil
}

// The transaction's complete trust boundary (period, identity, pinned key,
// sequence and FUP threshold) is held until the caller commits the receipt.
func collectInTx(ctx context.Context, tx *sql.Tx, authenticatedNode uuid.UUID, a Assignment,
	reader UsageReader) (Receipt, error) {
	var subscription string
	var key []byte
	var revoked bool
	err := tx.QueryRowContext(ctx, `SELECT a.subscription_id,c.public_key,c.revoked
		FROM elx_accounting_assignments a
		JOIN elx_core_identities c ON c.node_id=a.node_id AND c.incarnation=a.incarnation
		WHERE a.node_id=$1 AND a.executor_id=$2 AND a.incarnation=$3 AND
			a.accounting_id=$4 AND a.generation=$5 AND a.period_id=$6
		FOR SHARE OF a,c`, a.NodeID, a.ExecutorID, a.Incarnation,
		a.AccountingID, a.Generation, a.PeriodID).Scan(&subscription, &key, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return Receipt{}, ErrStream
	}
	if err != nil {
		return Receipt{}, err
	}
	if revoked || len(key) != ed25519.PublicKeySize || subscription == "" {
		return Receipt{}, ErrStream
	}
	verified, err := reader.ReadUsage(ctx, subscription, ed25519.PublicKey(key))
	if err != nil {
		return Receipt{}, err
	}
	if verified.Incarnation != a.Incarnation {
		return Receipt{}, ErrStream
	}
	s := Sample{
		NodeID: a.NodeID, ExecutorID: a.ExecutorID, Incarnation: a.Incarnation,
		AccountingID: a.AccountingID, Generation: a.Generation, PeriodID: a.PeriodID,
		Sequence: verified.Sequence, SampledAt: verified.SampledAt,
		UpBytes: verified.UpBytes, DownBytes: verified.DownBytes,
	}
	if err := validateSample(authenticatedNode, s); err != nil {
		return Receipt{}, err
	}
	return ingestSample(ctx, tx, s)
}
