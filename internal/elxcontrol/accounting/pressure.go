package accounting

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"math"

	"github.com/ElXnet/ElX-control/internal/elxcontrol/corepolicy"
	"github.com/google/uuid"
)

// persistRemotePressure stores only a pinned, current, applied core policy.
// Call AFTER ingestSample: its entitlement budget lock serializes this
// snapshot against rate grants and FUP. A missing/unbound/transitioning
// source is simply unavailable for dynamic allocation, not billable usage.
func persistRemotePressure(ctx context.Context, tx *sql.Tx, binding RemoteBinding,
	period uuid.UUID, current corepolicy.PressureSample) error {
	if current.Incarnation != binding.Incarnation ||
		current.Sequence == 0 || current.Sequence > math.MaxInt64 ||
		current.Revision == 0 || current.Revision > math.MaxInt64 {
		return ErrRemoteEvidence
	}
	counters := []uint64{
		current.Upload.PayloadBytes, current.Download.PayloadBytes,
		current.Upload.BlockedCalls, current.Download.BlockedCalls,
		current.Upload.BlockedNanos, current.Download.BlockedNanos,
	}
	for _, value := range counters {
		if value > math.MaxInt64 {
			return ErrRemoteEvidence
		}
	}
	var resource sql.NullString
	err := tx.QueryRowContext(ctx, `SELECT resource_id::text
		FROM elx_accounting_assignments
		WHERE node_id=$1 AND executor_id=$2 AND incarnation=$3
		AND accounting_id=$4 AND generation=$5 AND period_id=$6
		AND active FOR SHARE`,
		binding.NodeID, binding.ExecutorID, binding.Incarnation,
		binding.AccountingID, binding.Generation, period).Scan(&resource)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrStream
	}
	if err != nil {
		return err
	}
	if !resource.Valid {
		// An unbound legacy usage stream can be billed, but is never a
		// trusted source of node/resource demand.
		return nil
	}
	var committedUp, committedDown int64
	var pending bool
	err = tx.QueryRowContext(ctx, `SELECT g.committed_up,g.committed_down,
		EXISTS(SELECT 1 FROM elx_rate_moves m
			WHERE m.node_id=g.node_id AND m.resource_id=g.resource_id AND NOT m.finalized)
		FROM elx_rate_grants g
		WHERE g.node_id=$1 AND g.resource_id=$2`, binding.NodeID, resource.String).
		Scan(&committedUp, &committedDown, &pending)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrStream
	}
	if err != nil {
		return err
	}
	if pending || committedUp <= 0 || committedDown <= 0 ||
		current.RateUp != uint64(committedUp) ||
		current.RateDown != uint64(committedDown) {
		// Do NOT claim a confirmed effective rate while the policy is
		// changing or has a rate different from Control's committed grant.
		// The existing high-watermark will become stale automatically.
		return nil
	}
	var old corepolicy.PressureSample
	err = tx.QueryRowContext(ctx, `SELECT incarnation,sequence,sampled_at,core_revision,
		up_bytes,down_bytes,up_blocked_calls,down_blocked_calls,
		up_blocked_nanos,down_blocked_nanos FROM elx_rate_pressure_samples
		WHERE node_id=$1 AND resource_id=$2 FOR UPDATE`,
		binding.NodeID, resource.String).
		Scan(&old.Incarnation, &old.Sequence, &old.SampledAt, &old.Revision,
			&old.Upload.PayloadBytes, &old.Download.PayloadBytes,
			&old.Upload.BlockedCalls, &old.Download.BlockedCalls,
			&old.Upload.BlockedNanos, &old.Download.BlockedNanos)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if err == nil {
		if validateErr := corepolicy.ValidatePressureProgress(old, current); validateErr != nil {
			return ErrRemoteEvidence
		}
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO elx_rate_pressure_samples
		(node_id,resource_id,incarnation,sequence,sampled_at,core_revision,
		policy_up,policy_down,up_bytes,down_bytes,
		up_blocked_calls,down_blocked_calls,up_blocked_nanos,down_blocked_nanos,
		up_waiters,down_waiters,received_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16,clock_timestamp())
		ON CONFLICT(node_id,resource_id) DO UPDATE SET
		sequence=EXCLUDED.sequence,sampled_at=EXCLUDED.sampled_at,
		core_revision=EXCLUDED.core_revision,
		policy_up=EXCLUDED.policy_up,policy_down=EXCLUDED.policy_down,
		up_bytes=EXCLUDED.up_bytes,down_bytes=EXCLUDED.down_bytes,
		up_blocked_calls=EXCLUDED.up_blocked_calls,
		down_blocked_calls=EXCLUDED.down_blocked_calls,
		up_blocked_nanos=EXCLUDED.up_blocked_nanos,
		down_blocked_nanos=EXCLUDED.down_blocked_nanos,
		up_waiters=EXCLUDED.up_waiters,down_waiters=EXCLUDED.down_waiters,
		received_at=EXCLUDED.received_at`,
		binding.NodeID, resource.String, current.Incarnation,
		int64(current.Sequence), current.SampledAt, int64(current.Revision),
		int64(current.RateUp), int64(current.RateDown),
		int64(current.Upload.PayloadBytes), int64(current.Download.PayloadBytes),
		int64(current.Upload.BlockedCalls), int64(current.Download.BlockedCalls),
		int64(current.Upload.BlockedNanos), int64(current.Download.BlockedNanos),
		int64(current.Upload.ActiveWaiters), int64(current.Download.ActiveWaiters))
	return err
}
