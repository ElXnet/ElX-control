package delivery

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/journal"
)

func TestDeliveryReplayAndAppliedReceipt(t *testing.T) {
	dsn := os.Getenv("ELX_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("ELX_TEST_POSTGRES_DSN is required for PostgreSQL integration")
	}
	require := func(err error) {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	cfg, err := pgx.ParseConfig(dsn)
	require(err)
	admin := stdlib.OpenDB(*cfg)
	defer admin.Close()
	var random [8]byte
	_, err = rand.Read(random[:])
	require(err)
	schema := "elx_delivery_test_" + hex.EncodeToString(random[:])
	_, err = admin.ExecContext(ctx, "CREATE SCHEMA "+schema)
	require(err)
	defer func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if _, err := admin.ExecContext(cleanup, "DROP SCHEMA "+schema+" CASCADE"); err != nil {
			t.Error(err)
		}
	}()
	cfg.RuntimeParams["search_path"] = schema
	db := stdlib.OpenDB(*cfg)
	defer db.Close()
	require(journal.Migrate(ctx, db))
	target := journal.Target{
		NodeID:     "00000000-0000-0000-0000-000000000001",
		ResourceID: "00000000-0000-0000-0000-000000000002",
	}
	id := "00000000-0000-0000-0000-000000000003"
	rev, err := journal.Enqueue(ctx, db, target, journal.Command{ID: id, Payload: []byte("policy")})
	require(err)
	service, err := New(db, testAuthority{assignment: Assignment{Epoch: 2, ExecutorID: "executor", Incarnation: "core"}})
	require(err)
	first, err := service.Next(ctx, target.NodeID, target)
	require(err)
	second, err := service.Next(ctx, target.NodeID, target)
	require(err)
	if first.ID != id || second.ID != id || first.PayloadHash != second.PayloadHash {
		t.Fatal("redelivery changed command identity")
	}
	receipt := AppliedReceipt{
		Target: target, OperationID: id, Revision: rev, Assignment: first.Assignment,
		PayloadHash: first.PayloadHash, StateHash: [32]byte{1}, RestartManifestHash: [32]byte{2},
	}
	require(service.Confirm(ctx, target.NodeID, receipt))
	require(service.Confirm(ctx, target.NodeID, receipt))
	if _, err := service.Next(ctx, target.NodeID, target); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("expected acknowledged command to leave pending queue, got %v", err)
	}
}
