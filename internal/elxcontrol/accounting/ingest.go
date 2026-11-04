// Package accounting ingests cumulative payload samples from provisioned streams.
package accounting

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrSample     = errors.New("invalid usage sample")
	ErrStream     = errors.New("unassigned accounting stream")
	ErrRegression = errors.New("cumulative counter regressed")
	ErrConflict   = errors.New("same sequence contains different counters")
)

type Sample struct {
	NodeID       uuid.UUID
	ExecutorID   uuid.UUID
	Incarnation  uuid.UUID
	AccountingID uuid.UUID
	Generation   int64
	PeriodID     uuid.UUID
	Sequence     int64
	SampledAt    time.Time
	UpBytes      int64
	DownBytes    int64
}

type Receipt struct {
	Sequence  int64 // Committed high-water mark.
	Duplicate bool
	Crossed   bool // This transaction created the FUP event.
}

// Ingest trusts authenticatedNode only when derived from verified node mTLS.
// A stream and its period must be provisioned before any data is accepted.
func Ingest(ctx context.Context, db *sql.DB, authenticatedNode uuid.UUID, s Sample) (Receipt, error) {
	if err := validateSample(authenticatedNode, s); err != nil {
		return Receipt{}, err
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return Receipt{}, err
	}
	defer tx.Rollback()
	out, err := ingestSample(ctx, tx, s)
	if err != nil {
		return Receipt{}, err
	}
	if err := tx.Commit(); err != nil {
		return Receipt{}, err
	}
	return out, nil
}

func validateSample(authenticatedNode uuid.UUID, s Sample) error {
	if authenticatedNode == uuid.Nil || authenticatedNode != s.NodeID ||
		s.ExecutorID == uuid.Nil || s.Incarnation == uuid.Nil || s.AccountingID == uuid.Nil ||
		s.Generation <= 0 || s.PeriodID == uuid.Nil || s.Sequence <= 0 || s.SampledAt.IsZero() ||
		s.UpBytes < 0 || s.DownBytes < 0 {
		return ErrSample
	}
	return nil
}

// ingestSample performs the cumulative high-watermark write and FUP threshold
// transition within the caller's transaction. The collector also holds pinned
// core identity/assignment locks in this same transaction.
func ingestSample(ctx context.Context, tx *sql.Tx, s Sample) (Receipt, error) {
	// Serialize the threshold transition against all rate-grant mutations.
	// Without this lock a concurrent increase could commit after the sample
	// crossed FUP while still observing the earlier (larger) budget.
	var entitlement uuid.UUID
	err := tx.QueryRowContext(ctx, `SELECT b.entitlement_id
		FROM elx_rate_budgets b JOIN elx_usage_periods p ON p.entitlement_id=b.entitlement_id
		WHERE p.id=$1 FOR UPDATE OF b`, s.PeriodID).Scan(&entitlement)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return Receipt{}, err
	}
	key := []any{s.NodeID, s.ExecutorID, s.Incarnation, s.AccountingID, s.Generation, s.PeriodID}
	const where = `node_id=$1 AND executor_id=$2 AND incarnation=$3 AND accounting_id=$4 AND generation=$5 AND period_id=$6`
	var seq, up, down int64
	err = tx.QueryRowContext(ctx, `SELECT sequence,up_bytes,down_bytes FROM elx_accounting_streams
		WHERE `+where+` FOR UPDATE`, key...).Scan(&seq, &up, &down)
	if errors.Is(err, sql.ErrNoRows) {
		return Receipt{}, ErrStream
	}
	if err != nil {
		return Receipt{}, err
	}
	if s.Sequence <= seq {
		if s.Sequence == seq && (s.UpBytes != up || s.DownBytes != down) {
			return Receipt{}, ErrConflict
		}
		if err := tx.Commit(); err != nil {
			return Receipt{}, err
		}
		return Receipt{Sequence: seq, Duplicate: true}, nil
	}
	if s.UpBytes < up || s.DownBytes < down {
		return Receipt{}, ErrRegression
	}

	var periodUp, periodDown, threshold, reducedUp, reducedDown int64
	var direction string
	// The timestamp is the sample time at the source. Late delivery still
	// contributes to that source period, including its exact end boundary.
	err = tx.QueryRowContext(ctx, `UPDATE elx_usage_periods
		SET up_bytes=up_bytes+$2,down_bytes=down_bytes+$3
		WHERE id=$1 AND $4>=starts_at AND $4<=ends_at
		RETURNING up_bytes,down_bytes,direction,threshold_bytes,reduced_up,reduced_down`,
		s.PeriodID, s.UpBytes-up, s.DownBytes-down, s.SampledAt).
		Scan(&periodUp, &periodDown, &direction, &threshold, &reducedUp, &reducedDown)
	if errors.Is(err, sql.ErrNoRows) {
		return Receipt{}, ErrSample
	}
	if err != nil {
		return Receipt{}, err
	}

	_, err = tx.ExecContext(ctx, `UPDATE elx_accounting_streams
		SET sequence=$7,up_bytes=$8,down_bytes=$9 WHERE `+where, append(key, s.Sequence, s.UpBytes, s.DownBytes)...)
	if err != nil {
		return Receipt{}, err
	}
	out := Receipt{Sequence: s.Sequence}
	if (direction == "up" && periodUp >= threshold) || (direction == "down" && periodDown >= threshold) ||
		(direction == "total" && periodUp >= threshold-periodDown) {
		insert, err := tx.ExecContext(ctx, `INSERT INTO elx_fup_events(period_id,reduced_up,reduced_down)
			VALUES ($1,$2,$3) ON CONFLICT DO NOTHING`, s.PeriodID, reducedUp, reducedDown)
		if err != nil {
			return Receipt{}, err
		}
		count, err := insert.RowsAffected()
		if err != nil {
			return Receipt{}, err
		}
		out.Crossed = count == 1
	}
	return out, nil
}
