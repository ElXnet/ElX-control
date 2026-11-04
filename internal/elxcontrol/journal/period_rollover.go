package journal

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
)

var ErrPeriod = errors.New("invalid or unprovisioned accounting schedule")

type PeriodAdvance struct {
	ScheduleID uuid.UUID
	PreviousID uuid.UUID
	PeriodID   uuid.UUID
	Advanced   bool
}

// AdvancePeriod atomically seals one period and inherits every stream's latest
// cumulative watermark. A late old-period sample will be rejected. Any
// unreported bytes between the last old watermark and the first new readback
// are attributed to the new period; exact wall-clock packet attribution is
// impossible with periodic cumulative counters alone.
func AdvancePeriod(ctx context.Context, db *sql.DB, scheduleID uuid.UUID, now time.Time) (PeriodAdvance, error) {
	out := PeriodAdvance{ScheduleID: scheduleID}
	if db == nil || scheduleID == uuid.Nil || now.IsZero() {
		return out, ErrPeriod
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return out, err
	}
	defer tx.Rollback()
	var entitlement, oldID uuid.UUID
	var cadence, zone string
	var enabled bool
	err = tx.QueryRowContext(ctx, `SELECT entitlement_id,current_period_id,cadence,timezone_name,enabled
		FROM elx_period_schedules WHERE id=$1 FOR UPDATE`, scheduleID).
		Scan(&entitlement, &oldID, &cadence, &zone, &enabled)
	if errors.Is(err, sql.ErrNoRows) {
		return out, ErrPeriod
	}
	if err != nil {
		return out, err
	}
	if !enabled {
		return out, tx.Commit()
	}

	var starts, ends time.Time
	var direction string
	var threshold, up, down int64
	err = tx.QueryRowContext(ctx, `SELECT starts_at,ends_at,direction,threshold_bytes,
		reduced_up,reduced_down FROM elx_usage_periods
		WHERE id=$1 AND entitlement_id=$2 AND schedule_id=$3 FOR UPDATE`,
		oldID, entitlement, scheduleID).Scan(&starts, &ends, &direction, &threshold, &up, &down)
	if errors.Is(err, sql.ErrNoRows) {
		return out, ErrPeriod
	}
	if err != nil {
		return out, err
	}
	if !ends.After(starts) || !now.Before(ends) && now.IsZero() {
		return out, ErrPeriod
	}
	if now.Before(ends) {
		return out, tx.Commit()
	}
	nextEnd, err := nextCalendarBoundary(ends, cadence, zone)
	if err != nil {
		return out, err
	}
	newID, err := uuid.NewRandom()
	if err != nil {
		return out, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO elx_usage_periods
		(id,entitlement_id,starts_at,ends_at,direction,threshold_bytes,
		reduced_up,reduced_down,schedule_id) VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9)`,
		newID, entitlement, ends, nextEnd, direction, threshold, up, down, scheduleID)
	if err != nil {
		return out, err
	}
	// Closing takes an update lock on each old accounting stream. A concurrent
	// Collect/Ingest must complete before the source watermark is cloned.
	_, err = tx.ExecContext(ctx, `UPDATE elx_accounting_streams SET closed=true WHERE period_id=$1`, oldID)
	if err != nil {
		return out, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO elx_accounting_streams
		(node_id,executor_id,incarnation,accounting_id,generation,period_id,
		sequence,up_bytes,down_bytes,closed)
		SELECT node_id,executor_id,incarnation,accounting_id,generation,$2,
			sequence,up_bytes,down_bytes,false
		FROM elx_accounting_streams WHERE period_id=$1`, oldID, newID)
	if err != nil {
		return out, err
	}
	_, err = tx.ExecContext(ctx, `INSERT INTO elx_accounting_assignments
		(node_id,executor_id,incarnation,accounting_id,generation,period_id,subscription_id)
		SELECT node_id,executor_id,incarnation,accounting_id,generation,$2,subscription_id
		FROM elx_accounting_assignments WHERE period_id=$1`, oldID, newID)
	if err != nil {
		return out, err
	}
	_, err = tx.ExecContext(ctx, `UPDATE elx_period_schedules SET current_period_id=$2
		WHERE id=$1`, scheduleID, newID)
	if err != nil {
		return out, err
	}
	if err := tx.Commit(); err != nil {
		return out, err
	}
	out.PreviousID, out.PeriodID, out.Advanced = oldID, newID, true
	return out, nil
}

// nextCalendarBoundary uses calendar arithmetic in an IANA zone, not fixed
// 24-hour increments: daylight saving can make a day 23 or 25 hours.
func nextCalendarBoundary(previousEnd time.Time, cadence, timezone string) (time.Time, error) {
	location, err := time.LoadLocation(timezone)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: unknown timezone: %v", ErrPeriod, err)
	}
	local := previousEnd.In(location)
	if local.Hour() != 0 || local.Minute() != 0 || local.Second() != 0 || local.Nanosecond() != 0 {
		return time.Time{}, ErrPeriod
	}
	var next time.Time
	switch cadence {
	case "day":
		next = local.AddDate(0, 0, 1)
	case "week":
		if local.Weekday() != time.Monday {
			return time.Time{}, ErrPeriod
		}
		next = local.AddDate(0, 0, 7)
	case "month":
		if local.Day() != 1 {
			return time.Time{}, ErrPeriod
		}
		next = local.AddDate(0, 1, 0)
	default:
		return time.Time{}, ErrPeriod
	}
	if !next.After(local) {
		return time.Time{}, ErrPeriod
	}
	return next.UTC(), nil
}

// AdvanceDue catches up delayed schedules without skipping source watermarks.
// All calls are idempotent under the schedule row lock. A long outage of more
// than 96 cycles requires operator reconciliation rather than silent guessing.
func AdvanceDue(ctx context.Context, db *sql.DB, now time.Time) (int, error) {
	if db == nil || now.IsZero() {
		return 0, ErrPeriod
	}
	rows, err := db.QueryContext(ctx, `SELECT id FROM elx_period_schedules
		WHERE enabled=true ORDER BY id`)
	if err != nil {
		return 0, err
	}
	var schedules []uuid.UUID
	for rows.Next() {
		var id uuid.UUID
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, err
		}
		schedules = append(schedules, id)
	}
	err = rows.Err()
	rows.Close()
	if err != nil {
		return 0, err
	}
	var count int
	for _, schedule := range schedules {
		settled := false
		for range 96 {
			a, err := AdvancePeriod(ctx, db, schedule, now)
			if err != nil {
				return count, err
			}
			if !a.Advanced {
				settled = true
				break
			}
			count++
		}
		if !settled {
			return count, fmt.Errorf("%w: more than 96 missed periods for schedule %s", ErrPeriod, schedule)
		}
	}
	return count, nil
}
