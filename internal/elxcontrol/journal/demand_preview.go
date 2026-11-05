package journal

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/ElXnet/ElX-control/internal/elxcontrol/allocation"
	"github.com/google/uuid"
)

// DemandEstimate is a non-authorizing view of TWO previously verified signed
// pressure samples. It proves neither a current Control lease at the core nor
// the physical number of devices. An operator cannot queue a grant directly
// from this read-only output.
type DemandEstimate struct {
	Target      Target
	Incarnation uuid.UUID
	Revision    int64
	ObservedAt  time.Time
	Requested   Rate
}

// PreviewDemand reads a transactionally consistent pair of signed samples
// and the current purchased/FUP budget. Missing, stale, rotating, unassigned,
// unpinned or transitioning sources are OMITTED. A caller MUST treat every
// absent target as frozen at its existing committed grant.
//
// This is read-only: a separate signed lease-acceptance proof must be
// verified before constructing journal.RateDemand{LeaseValid:true} for
// RebalanceDemand. A server-issued lease alone is not proof that the core
// accepted it, so this function never sets LeaseValid.
func PreviewDemand(ctx context.Context, db *sql.DB, entitlement string) ([]DemandEstimate, error) {
	u, err := uuid.Parse(entitlement)
	if db == nil || err != nil || u == uuid.Nil || u.String() != entitlement {
		return nil, ErrInvalid
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	limit, err := lockBudget(ctx, tx, entitlement)
	if err != nil {
		return nil, err
	}
	var now time.Time
	if err := tx.QueryRowContext(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
		return nil, err
	}
	rows, err := tx.QueryContext(ctx, `
		SELECT p.node_id::text,p.resource_id::text,p.incarnation::text,
		  p.sequence,p.sampled_at,p.core_revision,p.policy_up,p.policy_down,
		  p.up_bytes,p.down_bytes,p.up_blocked_calls,p.down_blocked_calls,
		  p.up_blocked_nanos,p.down_blocked_nanos,p.up_waiters,p.down_waiters,
		  p.previous_sequence,p.previous_sampled_at,p.previous_core_revision,
		  p.previous_policy_up,p.previous_policy_down,
		  p.previous_up_bytes,p.previous_down_bytes,
		  p.previous_up_blocked_calls,p.previous_down_blocked_calls,
		  p.previous_up_blocked_nanos,p.previous_down_blocked_nanos
		FROM elx_rate_pressure_samples p
		JOIN elx_rate_grants g USING(node_id,resource_id)
		JOIN elx_operation_targets t USING(node_id,resource_id)
		JOIN elx_core_identities c ON c.node_id=p.node_id AND c.incarnation=p.incarnation
		JOIN elx_entitlements e ON e.id=g.entitlement_id
		WHERE g.entitlement_id=$1
		  AND g.committed_up>0 AND g.committed_down>0
		  AND e.enabled AND e.valid_until>clock_timestamp()
		  AND NOT c.revoked AND c.public_key=g.barrier_public_key
		  AND p.core_revision=t.revision+1
		  AND p.policy_up=g.committed_up AND p.policy_down=g.committed_down
		  AND p.previous_sequence IS NOT NULL
		  AND p.previous_core_revision=p.core_revision
		  AND p.previous_policy_up=p.policy_up
		  AND p.previous_policy_down=p.policy_down
		  AND p.received_at>=clock_timestamp()-interval '10 seconds'
		  AND NOT EXISTS(SELECT 1 FROM elx_rate_moves m
			WHERE m.node_id=p.node_id AND m.resource_id=p.resource_id AND NOT m.finalized)
		  AND NOT EXISTS(SELECT 1 FROM elx_core_rotations rot
			WHERE rot.node_id=p.node_id AND rot.state='quiescing')
		  AND EXISTS (
		    SELECT 1 FROM elx_accounting_assignments a
		    JOIN elx_accounting_streams st ON
		      st.node_id=a.node_id AND st.executor_id=a.executor_id
		      AND st.incarnation=a.incarnation AND st.accounting_id=a.accounting_id
		      AND st.generation=a.generation AND st.period_id=a.period_id
		    JOIN elx_period_schedules sc ON sc.current_period_id=a.period_id
		    WHERE a.node_id=p.node_id AND a.resource_id=p.resource_id
		      AND a.incarnation=p.incarnation AND a.active
		      AND sc.entitlement_id=g.entitlement_id
		      AND st.primed AND NOT st.closed
		      AND st.last_received_at>=clock_timestamp()-interval '30 seconds'
		  )
		ORDER BY p.node_id,p.resource_id LIMIT 10001`, entitlement)
	if err != nil {
		return nil, err
	}
	out := make([]DemandEstimate, 0)
	for rows.Next() {
		var result DemandEstimate
		var boot string
		var sequence, revision, up, down, upBytes, downBytes int64
		var upBlocked, downBlocked, upNanos, downNanos, upWait, downWait int64
		var prevSeq, prevRev, prevUp, prevDown, prevUpBytes, prevDownBytes int64
		var prevUpBlocked, prevDownBlocked, prevUpNanos, prevDownNanos int64
		var sampledAt, prevSampledAt time.Time
		if err := rows.Scan(
			&result.Target.NodeID,&result.Target.ResourceID,&boot,
			&sequence,&sampledAt,&revision,&up,&down,
			&upBytes,&downBytes,&upBlocked,&downBlocked,
			&upNanos,&downNanos,&upWait,&downWait,
			&prevSeq,&prevSampledAt,&prevRev,&prevUp,&prevDown,
			&prevUpBytes,&prevDownBytes,&prevUpBlocked,&prevDownBlocked,
			&prevUpNanos,&prevDownNanos,
		); err != nil {
			rows.Close()
			return nil, err
		}
		if len(out) == maxRateTargets {
			rows.Close()
			return nil, ErrInvalid
		}
		incarnation, err := uuid.Parse(boot)
		if err != nil || incarnation == uuid.Nil {
			rows.Close()
			return nil, ErrInvalid
		}
		toCounter := func(payload, blocked, nanos, waiters int64) allocation.PressureCounters {
			return allocation.PressureCounters{
				PayloadBytes:uint64(payload), BlockedCalls:uint64(blocked),
				BlockedNanos:uint64(nanos), ActiveWaiters:uint64(waiters),
			}
		}
		window := allocation.DemandWindow{
			Previous: allocation.PressureSample{
				Incarnation:incarnation, Sequence:uint64(prevSeq),
				SampledAt:prevSampledAt, Revision:uint64(prevRev),
				Applied:allocation.Rates{Up:prevUp,Down:prevDown},
				Upload:toCounter(prevUpBytes,prevUpBlocked,prevUpNanos,0),
				Download:toCounter(prevDownBytes,prevDownBlocked,prevDownNanos,0),
			},
			Current: allocation.PressureSample{
				Incarnation:incarnation, Sequence:uint64(sequence),
				SampledAt:sampledAt, Revision:uint64(revision),
				Applied:allocation.Rates{Up:up,Down:down},
				Upload:toCounter(upBytes,upBlocked,upNanos,upWait),
				Download:toCounter(downBytes,downBlocked,downNanos,downWait),
			},
			Ceiling: allocation.Rates{Up:limit.Up,Down:limit.Down}, Now:now,
		}
		requested, err := allocation.EstimateDemand(window)
		if errors.Is(err, allocation.ErrDemandWindow) {
			// A delayed sample, a gap or a policy transition proves
			// nothing about spare bandwidth. The grant remains frozen.
			continue
		}
		if err != nil {
			rows.Close()
			return nil, err
		}
		result.Incarnation = incarnation
		result.Revision = revision
		result.ObservedAt = sampledAt
		result.Requested = Rate{Up:requested.Up,Down:requested.Down}
		out = append(out,result)
	}
	if err := rows.Err(); err != nil {
		rows.Close()
		return nil, err
	}
	rows.Close()
	if err := tx.Commit(); err != nil {
		return nil, err
	}
	return out, nil
}
