package journal

import (
	"context"
	"crypto/ed25519"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/accounting"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/corepolicy"
)

func TestNextCalendarBoundaryDSTAndMonth(t *testing.T) {
	loc, err := time.LoadLocation("Europe/Warsaw")
	checkError(t, err, nil)
	dst := time.Date(2026, 3, 29, 0, 0, 0, 0, loc)
	day, err := nextCalendarBoundary(dst, "day", "Europe/Warsaw")
	checkError(t, err, nil)
	if day.Sub(dst) != 23*time.Hour {
		t.Fatalf("calendar day at DST boundary must last 23h, got %s", day.Sub(dst))
	}
	month, err := nextCalendarBoundary(time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC), "month", "UTC")
	checkError(t, err, nil)
	if !month.Equal(time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)) {
		t.Fatal("calendar month rollover failed:", month)
	}
	_, err = nextCalendarBoundary(time.Date(2026, 3, 2, 0, 0, 0, 0, time.UTC), "month", "UTC")
	checkError(t, err, ErrPeriod)
	_, err = nextCalendarBoundary(time.Date(2026, 3, 3, 0, 0, 0, 0, time.UTC), "week", "UTC")
	checkError(t, err, ErrPeriod)
	_, err = nextCalendarBoundary(dst, "day", "not/a/real/zone")
	checkError(t, err, ErrPeriod)
}

func TestAdvancePeriodAtomicWatermarkNoDoubleCharge(t *testing.T) {
	ctx, db := testDatabase(t)
	entitlement, schedule, oldPeriod := uuid.New(), uuid.New(), uuid.New()
	start := time.Now().UTC().Truncate(24*time.Hour).Add(-24 * time.Hour)
	end := start.AddDate(0, 0, 1)
	_, err := db.ExecContext(ctx, `INSERT INTO elx_entitlements(id,active_slots,valid_until)
		VALUES($1,2,clock_timestamp()+interval '1 day')`, entitlement)
	checkError(t, err, nil)
	_, err = db.ExecContext(ctx, `INSERT INTO elx_usage_periods
		(id,entitlement_id,starts_at,ends_at,direction,threshold_bytes,reduced_up,reduced_down,up_bytes,down_bytes)
		VALUES($1,$2,$3,$4,'total',1000,20,20,60,90)`, oldPeriod, entitlement, start, end)
	checkError(t, err, nil)
	_, err = db.ExecContext(ctx, `INSERT INTO elx_period_schedules
		(id,entitlement_id,cadence,timezone_name,current_period_id)
		VALUES($1,$2,'day','UTC',$3)`, schedule, entitlement, oldPeriod)
	checkError(t, err, nil)
	_, err = db.ExecContext(ctx, `UPDATE elx_usage_periods SET schedule_id=$2 WHERE id=$1`,
		oldPeriod, schedule)
	checkError(t, err, nil)
	a := accounting.Sample{
		NodeID: uuid.New(), ExecutorID: uuid.New(), Incarnation: uuid.New(),
		AccountingID: uuid.New(), Generation: 1, PeriodID: oldPeriod,
		Sequence: 7, SampledAt: start.Add(time.Hour),
		UpBytes: 60, DownBytes: 90,
	}
	key, _, err := ed25519.GenerateKey(nil)
	checkError(t, err, nil)
	_, err = db.ExecContext(ctx, `INSERT INTO elx_core_identities
		(node_id,incarnation,public_key) VALUES($1,$2,$3)`, a.NodeID, a.Incarnation, []byte(key))
	checkError(t, err, nil)
	_, err = db.ExecContext(ctx, `INSERT INTO elx_accounting_streams
		(node_id,executor_id,incarnation,accounting_id,generation,period_id,sequence,up_bytes,down_bytes)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`, a.NodeID, a.ExecutorID, a.Incarnation,
		a.AccountingID, a.Generation, a.PeriodID, a.Sequence, a.UpBytes, a.DownBytes)
	checkError(t, err, nil)
	_, err = db.ExecContext(ctx, `INSERT INTO elx_accounting_assignments
		(node_id,executor_id,incarnation,accounting_id,generation,period_id,subscription_id)
		VALUES($1,$2,$3,$4,$5,$6,'lab')`, a.NodeID, a.ExecutorID, a.Incarnation,
		a.AccountingID, a.Generation, a.PeriodID)
	checkError(t, err, nil)

	// Two concurrent reconcilers must advance this schedule exactly once.
	var wg sync.WaitGroup
	type outcome struct { next PeriodAdvance; err error }
	results := make(chan outcome, 2)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			p, err := AdvancePeriod(ctx, db, schedule, end.Add(time.Hour))
			results <- outcome{p, err}
		}()
	}
	wg.Wait()
	close(results)
	var next PeriodAdvance
	var transitions int
	for result := range results {
		checkError(t, result.err, nil)
		if result.next.Advanced {
			transitions++
			next = result.next
		}
	}
	if transitions != 1 || next.PreviousID != oldPeriod || next.PeriodID == uuid.Nil {
		t.Fatalf("rollover repeated or missing: count=%d next=%+v", transitions, next)
	}

	var closed bool
	err = db.QueryRowContext(ctx, `SELECT closed FROM elx_accounting_streams WHERE period_id=$1`,
		oldPeriod).Scan(&closed)
	checkError(t, err, nil)
	if !closed { t.Fatal("previous period was not sealed") }

	late := a
	late.Sequence = 8
	late.UpBytes, late.DownBytes = 75, 95
	late.SampledAt = end.Add(-time.Minute)
	_, err = accounting.Ingest(ctx, db, a.NodeID, late)
	checkError(t, err, accounting.ErrStream)

	newSample := late
	newSample.PeriodID = next.PeriodID
	newSample.SampledAt = end.Add(30*time.Minute)
	receipt, err := accounting.Ingest(ctx, db, newSample.NodeID, newSample)
	checkError(t, err, nil)
	if receipt.Sequence != 8 || receipt.Duplicate {
		t.Fatalf("new period watermark wrong: %+v", receipt)
	}
	var up, down int64
	err = db.QueryRowContext(ctx, `SELECT up_bytes,down_bytes FROM elx_usage_periods WHERE id=$1`,
		next.PeriodID).Scan(&up, &down)
	checkError(t, err, nil)
	if up != 15 || down != 5 {
		t.Fatalf("old cumulative bytes charged twice: new period %d/%d", up, down)
	}

	binding := accounting.Assignment{NodeID: a.NodeID, ExecutorID: a.ExecutorID,
		Incarnation: a.Incarnation, AccountingID: a.AccountingID,
		Generation: a.Generation}
	usage := corepolicy.Usage{Incarnation: a.Incarnation, Sequence: 9,
		SampledAt: end.Add(40*time.Minute), UpBytes: 80, DownBytes: 100}
	_, err = accounting.CollectCurrent(ctx, db, a.NodeID, schedule, binding,
		signedUsageStub{"lab", key, usage})
	checkError(t, err, nil)
	err = db.QueryRowContext(ctx, `SELECT up_bytes,down_bytes FROM elx_usage_periods WHERE id=$1`,
		next.PeriodID).Scan(&up, &down)
	checkError(t, err, nil)
	if up != 20 || down != 10 {
		t.Fatalf("signed usage after rollover incorrect: %d/%d", up, down)
	}
	replayed, err := AdvancePeriod(ctx, db, schedule, end.Add(time.Hour))
	checkError(t, err, nil)
	if replayed.Advanced { t.Fatalf("rollover replay created a new period: %+v", replayed) }
	// A controller restarted after several missed deadlines must advance every
	// missed calendar boundary without duplicating the last cumulative sample.
	steps, err := AdvanceDue(ctx, db, end.Add(72*time.Hour))
	checkError(t, err, nil)
	if steps != 3 {
		t.Fatalf("missed boundary recovery advanced %d periods, want 3", steps)
	}
	var current uuid.UUID
	err = db.QueryRowContext(ctx, `SELECT current_period_id FROM elx_period_schedules WHERE id=$1`,
		schedule).Scan(&current)
	checkError(t, err, nil)
	var bytesUp, bytesDown int64
	err = db.QueryRowContext(ctx, `SELECT up_bytes,down_bytes FROM elx_accounting_streams
		WHERE period_id=$1`, current).Scan(&bytesUp, &bytesDown)
	checkError(t, err, nil)
	if bytesUp != 80 || bytesDown != 100 {
		t.Fatalf("cumulative stream watermark changed during catchup: %d/%d", bytesUp, bytesDown)
	}
}

func TestAdvanceDueDoesNotTouchUnscheduledPeriods(t *testing.T) {
	ctx, db := testDatabase(t)
	count, err := AdvanceDue(ctx, db, time.Now())
	checkError(t, err, nil)
	if count != 0 { t.Fatal("unconfigured schedule was advanced") }
	_, err = AdvancePeriod(context.Background(), nil, uuid.New(), time.Now())
	checkError(t, err, ErrPeriod)
}
