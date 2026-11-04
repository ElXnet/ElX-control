package accounting

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"

	"github.com/google/uuid"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/corepolicy"
)

// Assignment is provisioned by Control. Values arriving from the end-user or
// from the VPN protocol must never be treated as authoritative assignments.
type Assignment struct {
	NodeID       uuid.UUID
	ExecutorID   uuid.UUID
	Incarnation  uuid.UUID
	AccountingID uuid.UUID
	Generation   int64
	PeriodID     uuid.UUID
}

// UsageReader must verify the signed ElXray usage response using the provided
// pinned key and a fresh challenge. corepolicy.Client implements this contract.
type UsageReader interface {
	ReadUsage(context.Context, string, ed25519.PublicKey) (corepolicy.Usage, error)
}

// Collect reads a pinned core's signed cumulative counters and applies exactly
// one database high-watermark update. Assignment, identity and usage changes
// share a transaction: revocation cannot race acceptance of the sample.
// authenticatedNode MUST come from verified mTLS or trusted local supervisor.
func Collect(ctx context.Context, db *sql.DB, authenticatedNode uuid.UUID, a Assignment, reader UsageReader) (Receipt, error) {
	if db == nil || reader == nil || authenticatedNode == uuid.Nil || authenticatedNode != a.NodeID ||
		a.ExecutorID == uuid.Nil || a.Incarnation == uuid.Nil || a.AccountingID == uuid.Nil ||
		a.Generation <= 0 || a.PeriodID == uuid.Nil {
		return Receipt{}, ErrSample
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return Receipt{}, err
	}
	defer tx.Rollback()

	var subscription string
	var key []byte
	var revoked bool
	err = tx.QueryRowContext(ctx, `SELECT a.subscription_id,c.public_key,c.revoked
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
	receipt, err := ingestSample(ctx, tx, s)
	if err != nil {
		return Receipt{}, err
	}
	if err := tx.Commit(); err != nil {
		return Receipt{}, err
	}
	return receipt, nil
}
