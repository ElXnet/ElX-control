package main

import (
	"context"
	"errors"
	"testing"

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

func TestFUPWorkerCancelsWithoutDatabaseQuery(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := runFUP(ctx, nil, nil, true); err != nil {
		t.Fatal("cancelled worker contacted the database:", err)
	}
}
