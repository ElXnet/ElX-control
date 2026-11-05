package journal

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
)

var (
	ErrManagedRate = errors.New("target is managed by the rate budget")
	ErrRateBudget  = errors.New("insufficient uncommitted rate budget")
	ErrRateBarrier = errors.New("signed rate barrier required")
)

const maxRate = 1 << 40

type Rate struct{ Up, Down int64 }

func (r Rate) valid() bool {
	return r.Up >= 0 && r.Up <= maxRate && r.Down >= 0 && r.Down <= maxRate && (r.Up == 0) == (r.Down == 0)
}

// QueueRateMove reserves a target's maximum possible usage and writes the
// policy operation in the same transaction. Provisioning must establish the
// baseline against the live core before enabling a target in this ledger.
func QueueRateMove(ctx context.Context, db *sql.DB, entitlement string, target Target, operationID string, expected int64, desired Rate) (int64, error) {
	if db == nil || !desired.valid() || expected < 0 || expected > math.MaxInt64-2 {
		return 0, ErrInvalid
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return 0, err
	}
	defer tx.Rollback()
	limit, err := lockBudget(ctx, tx, entitlement)
	if err != nil {
		return 0, err
	}
	rev, err := queueRateMoveTx(ctx, tx, entitlement, target, operationID, expected, desired, limit)
	if err != nil {
		return 0, err
	}
	return rev, tx.Commit()
}

// queueRateMoveTx performs authorization and durable reservation while the
// caller still holds lockBudget's entitlement row lock. Internal schedulers
// use this to keep verified demand, leader epoch, FUP budget and enqueue in
// ONE transaction. No caller may commit the grant based on an earlier read.
func queueRateMoveTx(ctx context.Context, tx *sql.Tx, entitlement string, target Target,
	operationID string, expected int64, desired, limit Rate) (int64, error) {
	if !validRateTarget(target) || !desired.valid() ||
		expected < 0 || expected > math.MaxInt64-2 {
		return 0, ErrInvalid
	}
	var err error
	// A quiescing core may only receive signed disable/drain operations.
	// Positive rates cannot be queued while the old core is being fenced.
	if desired.Up>0 || desired.Down>0 {
		var rotating bool
		err=tx.QueryRowContext(ctx,`SELECT EXISTS(SELECT 1 FROM elx_core_rotations
			WHERE node_id=$1 AND state='quiescing')`,target.NodeID).Scan(&rotating)
		if err!=nil{return 0,err}
		if rotating{return 0,ErrPending}
	}
	var current Rate
	err = tx.QueryRowContext(ctx, `SELECT committed_up,committed_down FROM elx_rate_grants
		WHERE entitlement_id=$1 AND node_id=$2 AND resource_id=$3`,
		entitlement, target.NodeID, target.ResourceID).Scan(&current.Up, &current.Down)
	if err != nil {
		return 0, err
	}
	payload, err := json.Marshal(struct {
		Up, Down int64
		Disabled bool
	}{max(1, desired.Up), max(1, desired.Down), desired.Up == 0})
	if err != nil {
		return 0, err
	}
	cmd := Command{ID: operationID, ExpectedRevision: expected, Payload: payload}

	var previous Rate
	err = tx.QueryRowContext(ctx, `SELECT desired_up,desired_down FROM elx_rate_moves
		WHERE node_id=$1 AND resource_id=$2 AND operation_id=$3`, target.NodeID, target.ResourceID, operationID).
		Scan(&previous.Up, &previous.Down)
	if err == nil {
		if previous != desired {
			return 0, ErrConflict
		}
		rev, err := enqueue(ctx, tx, target, cmd, true)
		if err != nil {
			return 0, err
		}
		return rev, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return 0, err
	}

	var occupied Rate
	var pending bool
	err = tx.QueryRowContext(ctx, `SELECT
		COALESCE(sum(GREATEST(g.committed_up,m.desired_up)) FILTER(WHERE (g.node_id,g.resource_id)<>($2::uuid,$3::uuid)),0),
		COALESCE(sum(GREATEST(g.committed_down,m.desired_down)) FILTER(WHERE (g.node_id,g.resource_id)<>($2::uuid,$3::uuid)),0),
		COALESCE(bool_or(m.operation_id IS NOT NULL) FILTER(WHERE (g.node_id,g.resource_id)=($2::uuid,$3::uuid)),false)
		FROM elx_rate_grants g LEFT JOIN elx_rate_moves m ON
		(g.node_id,g.resource_id)=(m.node_id,m.resource_id) AND NOT m.finalized
		WHERE g.entitlement_id=$1`, entitlement, target.NodeID, target.ResourceID).Scan(&occupied.Up, &occupied.Down, &pending)
	if err != nil {
		return 0, err
	}
	if pending {
		return 0, ErrPending
	}
	// An active FUP cap can be below already committed grants. Allow
	// monotone reductions to converge safely; refuse any directional increase
	// unless both existing and pending commitments fit the effective cap.
	if (desired.Up > current.Up && (desired.Up > limit.Up || occupied.Up > limit.Up-desired.Up)) ||
		(desired.Down > current.Down && (desired.Down > limit.Down || occupied.Down > limit.Down-desired.Down)) {
		return 0, ErrRateBudget
	}

	var existingOperation bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM elx_operations
		WHERE node_id=$1 AND resource_id=$2 AND operation_id=$3)`, target.NodeID, target.ResourceID, operationID).
		Scan(&existingOperation)
	if err != nil {
		return 0, err
	}
	if existingOperation {
		return 0, ErrConflict
	}
	rev, err := enqueue(ctx, tx, target, cmd, true)
	if err != nil {
		return 0, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO elx_rate_moves(node_id,resource_id,operation_id,desired_up,desired_down)
		VALUES($1,$2,$3,$4,$5)`, target.NodeID, target.ResourceID, operationID, desired.Up, desired.Down)
	if err != nil {
		return 0, err
	}
	return rev, nil
}

func lockBudget(ctx context.Context, tx *sql.Tx, entitlement string) (Rate, error) {
	var limit Rate
	err := tx.QueryRowContext(ctx, `SELECT up_limit,down_limit FROM elx_rate_budgets
		WHERE entitlement_id=$1 FOR UPDATE`, entitlement).Scan(&limit.Up, &limit.Down)
	if err != nil {
		return Rate{}, err
	}
	// Applied FUP can only tighten the purchased budget. The row lock above
	// serializes rate moves; events are idempotent and monotonic for each
	// period. All active periods contribute their strictest cap.
	var fupUp, fupDown sql.NullInt64
	err = tx.QueryRowContext(ctx, `SELECT MIN(e.reduced_up),MIN(e.reduced_down)
		FROM elx_fup_events e JOIN elx_usage_periods p ON p.id=e.period_id
		WHERE p.entitlement_id=$1 AND p.starts_at<=clock_timestamp()
			AND p.ends_at>clock_timestamp()
		AND (p.schedule_id IS NULL OR EXISTS(SELECT 1 FROM elx_period_schedules fs WHERE fs.id=p.schedule_id AND fs.enabled))`, entitlement).Scan(&fupUp, &fupDown)
	if err != nil {
		return Rate{}, err
	}
	if fupUp.Valid {
		limit.Up = min(limit.Up, fupUp.Int64)
	}
	if fupDown.Valid {
		limit.Down = min(limit.Down, fupDown.Int64)
	}
	return limit, nil
}

// FinalizeRateMove needs an applied journal receipt. A direction that decreases
// additionally needs a core barrier proof, distinct from the ordinary policy
// readback. Until then both the previous and the potential new commitments
// remain accounted for. The barrier protocol is intentionally not inferred
// from a successful SetSubscription or a disabled policy ACK.
func FinalizeRateMove(ctx context.Context, db *sql.DB, entitlement string, target Target, operationID string, barrier []byte) error {
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := lockBudget(ctx, tx, entitlement); err != nil {
		return err
	}
	var current, desired Rate
	var epoch, revision int64
	var key []byte
	var applied, finalized bool
	err = tx.QueryRowContext(ctx, `SELECT g.committed_up,g.committed_down,g.epoch,g.barrier_public_key,
		m.desired_up,m.desired_down,m.finalized,o.revision,o.applied_at IS NOT NULL
		FROM elx_rate_grants g JOIN elx_rate_moves m USING(node_id,resource_id)
		JOIN elx_operations o USING(node_id,resource_id,operation_id)
		WHERE g.entitlement_id=$1 AND g.node_id=$2 AND g.resource_id=$3 AND m.operation_id=$4`,
		entitlement, target.NodeID, target.ResourceID, operationID).
		Scan(&current.Up, &current.Down, &epoch, &key, &desired.Up, &desired.Down, &finalized, &revision, &applied)
	if err != nil {
		return err
	}
	if finalized {
		return tx.Commit()
	}
	if !applied {
		return ErrPending
	}
	needBarrier:=desired.Up < current.Up || desired.Down < current.Down ||
		(desired.Up==0 && desired.Down==0)
	if needBarrier {
		message := rateBarrierMessage(entitlement, target, operationID, epoch, revision, desired)
		if len(key) != ed25519.PublicKeySize || !ed25519.Verify(ed25519.PublicKey(key), message, barrier) {
			return ErrRateBarrier
		}
	}
	_, err = tx.ExecContext(ctx, `UPDATE elx_rate_grants SET committed_up=$3,committed_down=$4
		WHERE node_id=$1 AND resource_id=$2`, target.NodeID, target.ResourceID, desired.Up, desired.Down)
	if err != nil {
		return err
	}
	_, err = tx.ExecContext(ctx, `UPDATE elx_rate_moves SET finalized=true,
		barrier_signature=$4,barrier_at=CASE WHEN $4::bytea IS NOT NULL THEN clock_timestamp() ELSE NULL END
		WHERE node_id=$1 AND resource_id=$2 AND operation_id=$3`,
		target.NodeID, target.ResourceID, operationID, func() []byte {
			if needBarrier{return barrier}
			return nil
		}())
	if err != nil {
		return err
	}
	return tx.Commit()
}

func rateBarrierMessage(entitlement string, target Target, operation string, epoch, revision int64, desired Rate) []byte {
	return fmt.Appendf(nil, "elx-rate-barrier-v1\n%s\n%s\n%s\n%s\n%d\n%d\n%d\n%d",
		entitlement, target.NodeID, target.ResourceID, operation, epoch, revision, desired.Up, desired.Down)
}
