package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/journal"
)

// reconcileFUP scans only entitlements with a CURRENT FUP event. Once an
// event expires, no automatic increases are performed: an operator-controlled
// plan must establish and verify the new rate budget before raising speeds.
func reconcileFUP(ctx context.Context, db *sql.DB, specific string) error {
	entitlements := []string{}
	if specific != "" {
		id, err := uuid.Parse(specific)
		if err != nil || id == uuid.Nil || id.String() != specific {
			return journal.ErrInvalid
		}
		entitlements = append(entitlements, specific)
	} else {
		rows, err := db.QueryContext(ctx, `SELECT DISTINCT p.entitlement_id
			FROM elx_usage_periods p JOIN elx_fup_events e ON e.period_id=p.id
			WHERE p.starts_at<=clock_timestamp() AND p.ends_at>clock_timestamp()
			ORDER BY p.entitlement_id`)
		if err != nil {
			return err
		}
		for rows.Next() {
			var id string
			if err := rows.Scan(&id); err != nil {
				rows.Close()
				return err
			}
			entitlements = append(entitlements, id)
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return err
		}
	}
	for _, id := range entitlements {
		result, err := journal.ReconcileFUP(ctx, db, id)
		if err != nil {
			return fmt.Errorf("reconcile %s: %w", id, err)
		}
		if result.Queued > 0 || result.Pending > 0 {
			if err := json.NewEncoder(os.Stdout).Encode(result); err != nil {
				return err
			}
		}
	}
	return nil
}

func runFUP(ctx context.Context, db *sql.DB, args []string, continuous bool) error {
	fs := flag.NewFlagSet("reconcile-fup", flag.ContinueOnError)
	target := fs.String("entitlement", "", "optional entitlement UUID (default: all active FUP events)")
	interval := fs.Duration("interval", 5*time.Second, "reconciliation interval in continuous mode")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *interval < time.Second || *interval > time.Hour {
		return errors.New("FUP interval must be 1s..1h; no positional arguments accepted")
	}
	if err := reconcileFUP(ctx, db, *target); err != nil || !continuous {
		return err
	}
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
			if err := reconcileFUP(ctx, db, *target); err != nil {
				// Fail closed. Do not continue silently after a database or
				// authority failure; the service supervisor restarts us.
				return err
			}
		}
	}
}
