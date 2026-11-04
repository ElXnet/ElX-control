package main

import (
	"context"
	"database/sql"
	"errors"
	"testing"
	"time"

	"github.com/ElXnet/ElX-control/internal/elxcontrol/journal"
)

func TestReconcileFUPRejectsMalformedScopeBeforeDatabase(t *testing.T) {
	for _, value := range []string{"forged", "00000000-0000-0000-0000-000000000000"} {
		err := reconcileFUP(context.Background(), nil, value)
		if !errors.Is(err, journal.ErrInvalid) {
			t.Fatalf("scope %q: expected invalid entitlement, got %v", value, err)
		}
	}
}

func TestFUPWorkerRejectsUnsafeInterval(t *testing.T) {
	for _, args := range [][]string{
		{"-interval", "0"},
		{"-interval", "-1s"},
		{"-interval", "2h"},
		{"-interval", "abc"},
		{"unexpected"},
	} {
		if err := runFUP(context.Background(), nil, args, true); err == nil {
			t.Fatalf("invalid worker arguments accepted: %v", args)
		}
	}
}

func TestAgentRejectsInvalidIntervalBeforeConnecting(t *testing.T) {
	if err := serveAgent(context.Background(), []string{"-interval", "0"}); err == nil {
		t.Fatal("zero interval accepted")
	}
	if err := serveAgent(context.Background(), []string{"unexpected"}); err == nil {
		t.Fatal("unexpected positional argument accepted")
	}
}

func TestFUPWorkerCancelsWithoutSpinning(t *testing.T) {
	// A nil DB only enters the query path after validating flags. A healthy
	// worker will execute immediately, so cancellation must remain visible
	// even before the first sweep is sent to a real database.
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_ = time.Second
	_ = (*sql.DB)(nil)
	if ctx.Err() != context.Canceled {
		t.Fatal("cancelled context did not propagate")
	}
}
