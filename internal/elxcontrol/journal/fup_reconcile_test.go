package journal

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestFairFUPSharesNeverExceedDemandOrCapacity(t *testing.T) {
	for _, tc := range []struct {
		capacity int64
		demand   []int64
		want     []int64
	}{
		{0, []int64{50, 30}, []int64{0, 0}},
		{3, []int64{50, 50, 50}, []int64{1, 1, 1}},
		{2, []int64{50, 50, 50}, []int64{1, 1, 0}},
		{20, []int64{2, 100, 100}, []int64{2, 9, 9}},
		{200, []int64{2, 5, 20}, []int64{2, 5, 20}},
	} {
		got := fairFUPShares(tc.demand, tc.capacity)
		if len(got) != len(tc.want) {
			t.Fatalf("invalid length: %v", got)
		}
		var sum int64
		for i, value := range got {
			if value != tc.want[i] || value > tc.demand[i] || value < 0 {
				t.Fatalf("capacity %d demand %v got %v want %v",
					tc.capacity, tc.demand, got, tc.want)
			}
			sum += value
		}
		if sum > tc.capacity {
			t.Fatalf("overallocated %d > %d", sum, tc.capacity)
		}
	}
}

func TestReconcileFUPQueuesAllNodesAndDeduplicates(t *testing.T) {
	ctx, db := testDatabase(t)
	entitlement := uuid.NewString()
	period := uuid.NewString()
	now := time.Now().UTC()
	_, err := db.ExecContext(ctx, `INSERT INTO elx_entitlements(id,active_slots,valid_until)
		VALUES($1,2,clock_timestamp()+interval '1 day')`, entitlement)
	checkError(t, err, nil)
	_, err = db.ExecContext(ctx, `INSERT INTO elx_rate_budgets VALUES($1,100,100)`, entitlement)
	checkError(t, err, nil)
	_, err = db.ExecContext(ctx, `INSERT INTO elx_usage_periods
		(id,entitlement_id,starts_at,ends_at,direction,threshold_bytes,reduced_up,reduced_down)
		VALUES($1,$2,$3,$4,'total',100,20,20)`,
		period, entitlement, now.Add(-time.Minute), now.Add(time.Hour))
	checkError(t, err, nil)
	_, err = db.ExecContext(ctx, `INSERT INTO elx_fup_events(period_id,reduced_up,reduced_down) VALUES($1,20,20)`, period)
	checkError(t, err, nil)
	for _, speed := range []int{60, 40} {
		node, resource := uuid.NewString(), uuid.NewString()
		_, err = db.ExecContext(ctx, `INSERT INTO elx_operation_targets(node_id,resource_id) VALUES($1,$2)`, node, resource)
		checkError(t, err, nil)
		_, err = db.ExecContext(ctx, `INSERT INTO elx_rate_grants
			(entitlement_id,node_id,resource_id,committed_up,committed_down,epoch,barrier_public_key)
			VALUES($1,$2,$3,$4,$4,1,$5)`, entitlement, node, resource, speed, make([]byte, 32))
		checkError(t, err, nil)
	}

	// Race two reconcilers. The durable rate journal must keep at most one
	// pending reduction per node, even when the jobs overlap.
	var wg sync.WaitGroup
	var total int
	var mu sync.Mutex
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			res, err := ReconcileFUP(ctx, db, entitlement)
			if err != nil {
				t.Errorf("reconcile: %v", err)
				return
			}
			if !res.Active {
				t.Error("active FUP was not detected")
			}
			mu.Lock()
			total += res.Queued
			mu.Unlock()
		}()
	}
	wg.Wait()
	if total != 2 {
		t.Fatalf("expected two durable reductions across nodes, got %d", total)
	}
	var count int
	var desiredUp, desiredDown int64
	err = db.QueryRowContext(ctx, `SELECT count(*),sum(desired_up),sum(desired_down)
		FROM elx_rate_moves m JOIN elx_rate_grants g USING(node_id,resource_id)
		WHERE g.entitlement_id=$1 AND NOT m.finalized`, entitlement).Scan(&count, &desiredUp, &desiredDown)
	checkError(t, err, nil)
	if count != 2 || desiredUp > 20 || desiredDown > 20 || desiredUp == 0 {
		t.Fatalf("unsafe FUP reductions: count=%d up=%d down=%d", count, desiredUp, desiredDown)
	}
	again, err := ReconcileFUP(ctx, db, entitlement)
	checkError(t, err, nil)
	if again.Queued != 0 || again.Pending != 2 {
		t.Fatalf("replaying planner changed durable operations: %+v", again)
	}

	// Period expiry removes the FUP cap from future planning. The queued
	// reductions remain durable and cannot be silently upgraded.
	_, err = db.ExecContext(ctx, `UPDATE elx_usage_periods SET ends_at=clock_timestamp()-interval '1 second'
		WHERE id=$1`, period)
	checkError(t, err, nil)
	expired, err := ReconcileFUP(ctx, db, entitlement)
	checkError(t, err, nil)
	if expired.Active || expired.Queued != 0 {
		t.Fatalf("expired FUP generated a command: %+v", expired)
	}
}

func TestReconcileFUPRejectsUnprovisionedID(t *testing.T) {
	for _, id := range []string{"", "not-a-uuid", uuid.Nil.String()} {
		_, err := ReconcileFUP(context.Background(), nil, id)
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("ID %q: got %v", id, err)
		}
	}
}
