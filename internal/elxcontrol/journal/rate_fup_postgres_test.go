package journal

import (
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestActiveFUPDoesNotBlockReductionOrAllowExpansion(t *testing.T) {
	ctx, db := testDatabase(t)
	entitlement, period, resource := uuid.NewString(), uuid.NewString(), uuid.NewString()
	a := Target{uuid.NewString(), resource}
	b := Target{uuid.NewString(), resource}
	now := time.Now().UTC()
	_, err := db.ExecContext(ctx, `INSERT INTO elx_entitlements(id,active_slots,valid_until)
		VALUES ($1,2,clock_timestamp()+interval '1 day')`, entitlement)
	checkError(t, err, nil)
	_, err = db.ExecContext(ctx, `INSERT INTO elx_rate_budgets VALUES($1,100,100)`, entitlement)
	checkError(t, err, nil)
	_, err = db.ExecContext(ctx, `INSERT INTO elx_usage_periods
		(id,entitlement_id,starts_at,ends_at,direction,threshold_bytes,reduced_up,reduced_down)
		VALUES($1,$2,$3,$4,'total',100,20,20)`,
		period, entitlement, now.Add(-time.Minute), now.Add(time.Hour))
	checkError(t, err, nil)
	_, err = db.ExecContext(ctx, `INSERT INTO elx_fup_events(period_id,reduced_up,reduced_down)
		VALUES($1,20,20)`, period)
	checkError(t, err, nil)
	for _, x := range []struct{ target Target; rate int64 }{{a, 60}, {b, 40}} {
		_, err = db.ExecContext(ctx, `INSERT INTO elx_operation_targets(node_id,resource_id)
			VALUES($1,$2)`, x.target.NodeID, x.target.ResourceID)
		checkError(t, err, nil)
		_, err = db.ExecContext(ctx, `INSERT INTO elx_rate_grants
			(entitlement_id,node_id,resource_id,committed_up,committed_down,epoch,barrier_public_key)
			VALUES ($1,$2,$3,$4,$4,1,$5)`,
			entitlement, x.target.NodeID, x.target.ResourceID, x.rate, make([]byte, 32))
		checkError(t, err, nil)
	}
	// FUP lowered the effective cap to 20, but 100 was already committed.
	// Reductions must still be queued; refusing them would deadlock recovery.
	reduce := uuid.NewString()
	_, err = QueueRateMove(ctx, db, entitlement, a, reduce, 0, Rate{20, 20})
	checkError(t, err, nil)
	_, err = QueueRateMove(ctx, db, entitlement, b, uuid.NewString(), 0, Rate{50, 50})
	checkError(t, err, ErrRateBudget)
	_, err = QueueRateMove(ctx, db, entitlement, b, uuid.NewString(), 0, Rate{20, 20})
	checkError(t, err, nil)
	_, err = QueueRateMove(ctx, db, entitlement, a, uuid.NewString(), 0, Rate{70, 70})
	checkError(t, err, ErrPending)
}
