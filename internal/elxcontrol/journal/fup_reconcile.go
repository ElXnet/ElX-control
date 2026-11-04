// Package journal stores durable Control commands and rate-grant decisions.
package journal

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"slices"

	"github.com/google/uuid"
)

// FUPReconcileResult counts durable reductions, not policies applied on nodes.
// A queued reduction does NOT release its old committed budget until a signed
// reduction barrier is accepted. Re-run after pending operations settle.
type FUPReconcileResult struct {
	EntitlementID string
	Active        bool
	Queued        int
	Pending       int
	Unchanged     int
}

type fupGrant struct {
	target  Target
	current Rate
	rev     int64
	pending bool
}

// ReconcileFUP queues only reductions against an active FUP cap. It never
// attempts to reallocate freed capacity or silently increase rates after a
// period expires. A policy delivery worker must apply queued commands.
func ReconcileFUP(ctx context.Context, db *sql.DB, entitlement string) (FUPReconcileResult, error) {
	out := FUPReconcileResult{EntitlementID: entitlement}
	id, err := uuid.Parse(entitlement)
	if db == nil || err != nil || id == uuid.Nil || id.String() != entitlement {
		return out, ErrInvalid
	}
	var cap Rate
	var fupUp, fupDown sql.NullInt64
	err = db.QueryRowContext(ctx, `SELECT LEAST(b.up_limit, COALESCE(MIN(e.reduced_up),b.up_limit)),
		LEAST(b.down_limit, COALESCE(MIN(e.reduced_down),b.down_limit)),
		MIN(e.reduced_up),MIN(e.reduced_down)
		FROM elx_rate_budgets b
		LEFT JOIN elx_usage_periods p ON p.entitlement_id=b.entitlement_id
		AND p.starts_at<=clock_timestamp() AND p.ends_at>clock_timestamp()
		LEFT JOIN elx_fup_events e ON e.period_id=p.id
		WHERE b.entitlement_id=$1
		GROUP BY b.entitlement_id,b.up_limit,b.down_limit`, entitlement).
		Scan(&cap.Up, &cap.Down, &fupUp, &fupDown)
	if err != nil {
		return out, err
	}
	if !fupUp.Valid || !fupDown.Valid {
		return out, nil
	}
	out.Active = true
	rows, err := db.QueryContext(ctx, `SELECT g.node_id,g.resource_id,g.committed_up,g.committed_down,
		t.revision,EXISTS(SELECT 1 FROM elx_rate_moves m
			WHERE m.node_id=g.node_id AND m.resource_id=g.resource_id AND NOT m.finalized)
		FROM elx_rate_grants g JOIN elx_operation_targets t
			ON t.node_id=g.node_id AND t.resource_id=g.resource_id
		WHERE g.entitlement_id=$1 ORDER BY g.node_id,g.resource_id`, entitlement)
	if err != nil {
		return out, err
	}
	var grants []fupGrant
	for rows.Next() {
		var g fupGrant
		if err := rows.Scan(&g.target.NodeID, &g.target.ResourceID,
			&g.current.Up, &g.current.Down, &g.rev, &g.pending); err != nil {
			rows.Close()
			return out, err
		}
		grants = append(grants, g)
		if len(grants) > 10000 {
			rows.Close()
			return out, ErrInvalid
		}
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return out, err
	}
	if len(grants) == 0 {
		return out, nil
	}

	currentUp, currentDown := make([]int64, len(grants)), make([]int64, len(grants))
	for i, g := range grants {
		currentUp[i], currentDown[i] = g.current.Up, g.current.Down
	}
	up := fairFUPShares(currentUp, cap.Up)
	down := fairFUPShares(currentDown, cap.Down)
	for i, g := range grants {
		desired := Rate{Up: up[i], Down: down[i]}
		// The local policy RPC requires both directions positive, or a full
		// disable. Discard spare headroom rather than sending partial unlimited.
		if desired.Up == 0 || desired.Down == 0 {
			desired = Rate{}
		}
		if desired.Up >= g.current.Up && desired.Down >= g.current.Down {
			out.Unchanged++
			continue
		}
		if g.pending {
			out.Pending++
			continue
		}
		op, err := uuid.NewRandom()
		if err != nil {
			return out, err
		}
		_, err = QueueRateMove(ctx, db, entitlement, g.target, op.String(), g.rev, desired)
		switch {
		case err == nil:
			out.Queued++
		case errors.Is(err, ErrPending), errors.Is(err, ErrRevision):
			out.Pending++
		default:
			return out, fmt.Errorf("queue FUP reduction for %s/%s: %w",
				g.target.NodeID, g.target.ResourceID, err)
		}
	}
	return out, nil
}

// fairFUPShares implements deterministic, integer weighted max-min without
// allocating above any target's existing grant. Equal weights prevent a busy
// node from monopolizing the reduced budget. Unused capacity is acceptable.
func fairFUPShares(demand []int64, capacity int64) []int64 {
	result := make([]int64, len(demand))
	if capacity <= 0 {
		return result
	}
	order := make([]int, 0, len(demand))
	for i, amount := range demand {
		if amount > 0 {
			order = append(order, i)
		}
	}
	slices.SortFunc(order, func(a, b int) int {
		if demand[a] != demand[b] {
			if demand[a] < demand[b] {
				return -1
			}
			return 1
		}
		return a - b
	})
	for i, index := range order {
		n := int64(len(order) - i)
		equal := capacity / n
		if demand[index] <= equal {
			result[index] = demand[index]
			capacity -= demand[index]
			continue
		}
		quotient, remainder := capacity/n, capacity%n
		for j, target := range order[i:] {
			result[target] = quotient
			if int64(j) < remainder {
				result[target]++
			}
		}
		break
	}
	return result
}
