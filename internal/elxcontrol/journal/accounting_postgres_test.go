package journal

import (
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/accounting"
)

func TestAccountingConcurrentStreamsAndFUP(t *testing.T) {
	ctx, db := testDatabase(t)
	entitlement, period, nextPeriod := uuid.New(), uuid.New(), uuid.New()
	start := time.Date(2026, 11, 4, 0, 0, 0, 0, time.UTC)
	end := start.Add(24 * time.Hour)
	_, err := db.ExecContext(ctx, `INSERT INTO elx_entitlements(id,active_slots,valid_until)
		VALUES($1,2,clock_timestamp()+interval '1 day')`, entitlement)
	checkError(t, err, nil)
	_, err = db.ExecContext(ctx, `INSERT INTO elx_usage_periods
		(id,entitlement_id,starts_at,ends_at,direction,threshold_bytes,reduced_up,reduced_down)
		VALUES($1,$2,$3,$4,'total',100,20,30),($5,$2,$4,$6,'total',100,20,30)`,
		period, entitlement, start, end, nextPeriod, end.Add(24*time.Hour))
	checkError(t, err, nil)
	a := accounting.Sample{NodeID: uuid.New(), ExecutorID: uuid.New(), Incarnation: uuid.New(),
		AccountingID: uuid.New(), Generation: 1, PeriodID: period, Sequence: 2,
		SampledAt: end, UpBytes: 30, DownBytes: 30}
	b := a
	b.NodeID, b.ExecutorID, b.Incarnation = uuid.New(), uuid.New(), uuid.New()
	next := a
	next.PeriodID, next.Incarnation, next.Sequence = nextPeriod, uuid.New(), 1
	next.SampledAt = end.Add(time.Second)
	next.UpBytes, next.DownBytes = 1, 2
	for _, s := range []accounting.Sample{a, b, next} {
		_, err := db.ExecContext(ctx, `INSERT INTO elx_accounting_streams
			(node_id,executor_id,incarnation,accounting_id,generation,period_id) VALUES($1,$2,$3,$4,$5,$6)`,
			s.NodeID, s.ExecutorID, s.Incarnation, s.AccountingID, s.Generation, s.PeriodID)
		checkError(t, err, nil)
	}
	type result struct {
		receipt accounting.Receipt
		err     error
	}
	results := make(chan result, 2)
	for _, s := range []accounting.Sample{a, b} {
		go func() {
			r, err := accounting.Ingest(ctx, db, s.NodeID, s)
			results <- result{r, err}
		}()
	}
	crossed := 0
	for range 2 {
		r := <-results
		checkError(t, r.err, nil)
		if r.receipt.Crossed {
			crossed++
		}
	}
	if crossed != 1 {
		t.Fatalf("threshold crossed %d times", crossed)
	}
	duplicate, err := accounting.Ingest(ctx, db, a.NodeID, a)
	checkError(t, err, nil)
	if !duplicate.Duplicate || duplicate.Sequence != 2 || duplicate.Crossed {
		t.Fatal(duplicate)
	}
	conflict := a
	conflict.UpBytes++
	_, err = accounting.Ingest(ctx, db, a.NodeID, conflict)
	checkError(t, err, accounting.ErrConflict)
	conflict.Sequence++
	conflict.UpBytes = 0
	_, err = accounting.Ingest(ctx, db, a.NodeID, conflict)
	checkError(t, err, accounting.ErrRegression)
	_, err = accounting.Ingest(ctx, db, b.NodeID, a)
	checkError(t, err, accounting.ErrSample)
	_, err = accounting.Ingest(ctx, db, next.NodeID, next)
	checkError(t, err, nil)
	for _, want := range []struct {
		id       uuid.UUID
		up, down int64
	}{{period, 60, 60}, {nextPeriod, 1, 2}} {
		var up, down int64
		err = db.QueryRowContext(ctx, `SELECT up_bytes,down_bytes FROM elx_usage_periods WHERE id=$1`, want.id).Scan(&up, &down)
		checkError(t, err, nil)
		if up != want.up || down != want.down {
			t.Fatalf("period %s got %d/%d", want.id, up, down)
		}
	}
	var eventCount int
	err = db.QueryRowContext(ctx, `SELECT count(*) FROM elx_fup_events WHERE period_id=$1`, period).Scan(&eventCount)
	checkError(t, err, nil)
	if eventCount != 1 {
		t.Fatalf("got %d events", eventCount)
	}
}
