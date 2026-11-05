package journal

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/ElXnet/ElX-control/internal/elxcontrol/allocation"
	"github.com/google/uuid"
)

// RateDemand is accepted only from an authenticated, lease-checked Control
// telemetry pipeline. It must never be populated directly from a customer
// request, an unauthenticated node report or an arbitrary HTTP header.
type RateDemand struct {
	Target     Target
	Requested  Rate
	Weight     int64
	ObservedAt time.Time
	LeaseValid bool
}

var ErrInactiveRateEntitlement = errors.New("rate entitlement is disabled or expired")

const (
	// A cached observation is not proof that a node still owns its grant.
	// The scheduler freezes missing, stale and unleased targets.
	maxDemandAge   = 10 * time.Second
	maxClockSkew   = 2 * time.Second
	maxRateTargets = 10000
)

// DemandRebalanceResult reports a committed journal operation (not a core
// application). Applied rates must be confirmed via signed core readback and,
// for a reduction, a distinct signed barrier before capacity is reusable.
type DemandRebalanceResult struct {
	OperationID       string
	Target            Target
	Desired           Rate
	Phase             string // lower, raise, waiting, stable
	FrozenTargets     int
	FrozenOverBudget  bool
}

// RebalanceDemand queues AT MOST ONE journal operation per call, allowing the
// agent to prove it has applied and (for reductions) drained the previous
// higher grant before Control recalculates any increases. This intentionally
// does not hold a DB transaction open while communicating with an ElXray node.
//
// The caller supplies fresh, authenticated demand observations. Missing,
// stale, unleased and quiescing targets remain frozen at their durable
// commitments. The journal, not this planner, authorizes each rate change.
func RebalanceDemand(ctx context.Context, db *sql.DB, entitlement string, observations []RateDemand) (DemandRebalanceResult, error) {
	out := DemandRebalanceResult{Phase: "stable"}
	id, err := uuid.Parse(entitlement)
	if db == nil || err != nil || id == uuid.Nil || id.String() != entitlement || len(observations) > maxRateTargets {
		return out, ErrInvalid
	}
	input := make(map[Target]RateDemand, len(observations))
	for _, d := range observations {
		if !validRateTarget(d.Target) || d.Weight < 1 || d.Weight > 1024 ||
			d.Requested.Up < 0 || d.Requested.Up > maxRate ||
			d.Requested.Down < 0 || d.Requested.Down > maxRate {
			return out, ErrInvalid
		}
		if _, exists := input[d.Target]; exists {
			return out, ErrInvalid
		}
		input[d.Target] = d
	}

	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return out, err
	}
	defer tx.Rollback()

	// This serializes the snapshot with QueueRateMove/FinalizeRateMove and
	// reads the effective purchased/FUP budget, not just the catalog limit.
	limit, err := lockBudget(ctx, tx, entitlement)
	if err != nil {
		return out, err
	}
	var now time.Time
	if err = tx.QueryRowContext(ctx, "SELECT clock_timestamp()").Scan(&now); err != nil {
		return out, err
	}
	// A disabled or expired subscription cannot receive a rate increase
	// simply because an old limiter continues reporting authenticated usage.
	// The revocation/drain workflow handles disabling its existing grants.
	var enabled bool
	var validUntil time.Time
	if err = tx.QueryRowContext(ctx, `SELECT enabled,valid_until FROM elx_entitlements
		WHERE id=$1`, entitlement).Scan(&enabled, &validUntil); err != nil {
		return out, err
	}
	if !enabled || !validUntil.After(now) {
		return out, ErrInactiveRateEntitlement
	}
	rows, err := tx.QueryContext(ctx, `SELECT g.node_id::text,g.resource_id::text,
		g.committed_up,g.committed_down,t.revision,
		EXISTS(SELECT 1 FROM elx_rate_moves m
			WHERE m.node_id=g.node_id AND m.resource_id=g.resource_id AND NOT m.finalized),
		EXISTS(SELECT 1 FROM elx_core_rotations c
			WHERE c.node_id=g.node_id AND c.state='quiescing')
		FROM elx_rate_grants g
		JOIN elx_operation_targets t ON t.node_id=g.node_id AND t.resource_id=g.resource_id
		WHERE g.entitlement_id=$1 ORDER BY g.node_id,g.resource_id
		LIMIT 10001`, entitlement)
	if err != nil {
		return out, err
	}
	type currentGrant struct {
		target  Target
		rate    Rate
		rev     int64
	}
	current := make(map[uuid.UUID]currentGrant)
	demands := make([]allocation.GrantDemand, 0)
	waiting := false
	for rows.Next() {
		var g currentGrant
		var pending, rotating bool
		if err = rows.Scan(&g.target.NodeID, &g.target.ResourceID, &g.rate.Up, &g.rate.Down, &g.rev, &pending, &rotating); err != nil {
			break
		}
		targetID := rateTargetID(g.target)
		if _, exists := current[targetID]; exists {
			err = ErrInvalid // fail closed on a theoretically colliding target ID
			break
		}
		current[targetID] = g
		if len(current) > maxRateTargets {
			err = ErrInvalid
			break
		}
		obs, present := input[g.target]
		if present {
			delete(input, g.target)
		}
		// No live session should be disabled merely because idle demand was
		// measured as zero. Explicit revocation is a separate signed drain.
		fresh := present && obs.LeaseValid &&
			!obs.ObservedAt.IsZero() &&
			!obs.ObservedAt.After(now.Add(maxClockSkew)) &&
			now.Sub(obs.ObservedAt) <= maxDemandAge &&
			obs.Requested.Up > 0 && obs.Requested.Down > 0
		frozen := !fresh || rotating || pending
		if pending {
			waiting = true
		}
		if frozen {
			out.FrozenTargets++
		}
		demand := allocation.GrantDemand{TargetID: targetID,
			Current: allocation.Rates{Up: g.rate.Up, Down: g.rate.Down},
			Frozen: frozen, Weight: 1}
		if fresh {
			demand.Requested = allocation.Rates{Up: obs.Requested.Up, Down: obs.Requested.Down}
			demand.Weight = obs.Weight
		}
		demands = append(demands, demand)
	}
	if err == nil {
		err = rows.Err()
	}
	rows.Close()
	if err != nil {
		return out, err
	}
	// Reject unknown targets. Otherwise a forged observation could make a
	// legitimate rate entry appear healthy or create an unintended grant.
	if len(input) != 0 {
		return out, ErrInvalid
	}
	if err = tx.Commit(); err != nil {
		return out, err
	}
	if waiting {
		out.Phase = "waiting"
		return out, nil
	}
	plan, err := allocation.PlanRebalance(
		allocation.Rates{Up: limit.Up, Down: limit.Down}, demands)
	if err != nil {
		return out, err
	}
	out.FrozenOverBudget = plan.FrozenOverBudget
	// Never use the old planned Raise after issuing Lower. Each call takes
	// a new locked snapshot; the next decision follows durable barriers.
	var next *allocation.Change
	if len(plan.Lower) != 0 {
		next = &plan.Lower[0]
		out.Phase = "lower"
	} else if len(plan.Raise) != 0 {
		next = &plan.Raise[0]
		out.Phase = "raise"
	}
	if next == nil {
		return out, nil
	}
	grant := current[next.TargetID]
	desired := Rate{Up: next.To.Up, Down: next.To.Down}
	if !desired.valid() {
		return DemandRebalanceResult{}, ErrInvalid
	}
	op, err := uuid.NewRandom()
	if err != nil {
		return DemandRebalanceResult{}, err
	}
	_, err = QueueRateMove(ctx, db, entitlement, grant.target, op.String(), grant.rev, desired)
	switch {
	case err == nil:
		out.OperationID, out.Target, out.Desired = op.String(), grant.target, desired
		return out, nil
	case errors.Is(err, ErrPending), errors.Is(err, ErrRevision), errors.Is(err, ErrRateBudget):
		// Another writer or a new FUP period invalidated the optimistic
		// proposal. Let the caller resnapshot rather than applying it stale.
		out.Phase = "waiting"
		return out, nil
	default:
		return DemandRebalanceResult{}, fmt.Errorf("rebalance entitlement %s target %s/%s: %w",
			entitlement, grant.target.NodeID, grant.target.ResourceID, err)
	}
}

func validRateTarget(t Target) bool {
	node, nodeErr := uuid.Parse(t.NodeID)
	resource, resourceErr := uuid.Parse(t.ResourceID)
	return nodeErr == nil && resourceErr == nil &&
		node != uuid.Nil && resource != uuid.Nil &&
		node.String() == t.NodeID && resource.String() == t.ResourceID
}

// A deterministic internal planning identity for the journal's node/resource
// pair. No assumption is made that one resource represents one device.
func rateTargetID(t Target) uuid.UUID {
	return uuid.NewSHA1(uuid.NameSpaceOID, []byte(t.NodeID+"/"+t.ResourceID))
}
