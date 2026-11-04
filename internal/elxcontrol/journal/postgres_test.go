package journal

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func testDatabase(t *testing.T) (context.Context, *sql.DB) {
	t.Helper()
	dsn := os.Getenv("ELX_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("ELX_TEST_POSTGRES_DSN is required for PostgreSQL integration")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	t.Cleanup(cancel)
	config, err := pgx.ParseConfig(dsn)
	checkError(t, err, nil)
	admin := stdlib.OpenDB(*config)
	t.Cleanup(func() { admin.Close() })
	var random [8]byte
	_, err = rand.Read(random[:])
	checkError(t, err, nil)
	name := "elx_test_" + hex.EncodeToString(random[:])
	_, err = admin.ExecContext(ctx, "CREATE SCHEMA "+name)
	checkError(t, err, nil)
	t.Cleanup(func() {
		cleanupCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, err := admin.ExecContext(cleanupCtx, "DROP SCHEMA "+name+" CASCADE")
		checkError(t, err, nil)
	})
	config.RuntimeParams["search_path"] = name
	db := stdlib.OpenDB(*config)
	t.Cleanup(func() { db.Close() })
	checkError(t, Migrate(ctx, db), nil)
	checkError(t, Migrate(ctx, db), nil)
	return ctx, db
}

func TestPostgresOperationLifecycle(t *testing.T) {
	ctx, db := testDatabase(t)

	target := Target{"00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000002"}
	cmd := Command{ID: "00000000-0000-0000-0000-000000000003", Payload: []byte("policy")}
	other := Command{ID: "00000000-0000-0000-0000-000000000004", Payload: []byte("next policy")}

	for range 2 {
		rev, err := Enqueue(ctx, db, target, cmd)
		checkError(t, err, nil)
		if rev != 1 {
			t.Fatalf("revision = %d, want 1", rev)
		}
	}
	checkPending(t, db, target, cmd.ID)
	_, err := Enqueue(ctx, db, target, other)
	checkError(t, err, ErrPending)
	conflict := cmd
	conflict.Payload = []byte("different")
	_, err = Enqueue(ctx, db, target, conflict)
	checkError(t, err, ErrConflict)

	hash := sha256.Sum256(cmd.Payload)
	wrongNode := target
	wrongNode.NodeID = other.ID
	checkError(t, ConfirmApplied(ctx, db, wrongNode, cmd.ID, 1, hash), ErrReceipt)
	checkError(t, ConfirmApplied(ctx, db, target, cmd.ID, 2, hash), ErrReceipt)
	checkError(t, ConfirmApplied(ctx, db, target, cmd.ID, 1, [32]byte{}), ErrReceipt)
	checkPending(t, db, target, cmd.ID)

	for range 2 {
		checkError(t, ConfirmApplied(ctx, db, target, cmd.ID, 1, hash), nil)
	}
	_, err = Pending(ctx, db, target)
	checkError(t, err, sql.ErrNoRows)
	_, err = Enqueue(ctx, db, target, other)
	checkError(t, err, ErrRevision)
	other.ExpectedRevision = 1
	_, err = Enqueue(ctx, db, target, other)
	checkError(t, err, nil)
	checkError(t, ConfirmApplied(ctx, db, target, cmd.ID, 1, hash), nil)
	checkPending(t, db, target, other.ID)
}

func TestPostgresConcurrentEnqueue(t *testing.T) {
	ctx, db := testDatabase(t)
	const count = 8
	db.SetMaxOpenConns(count)
	target := Target{"00000000-0000-0000-0000-000000000001", "00000000-0000-0000-0000-000000000002"}
	start := make(chan struct{})
	results := make(chan error, count)
	for i := range count {
		go func() {
			<-start
			_, err := Enqueue(ctx, db, target, Command{
				ID:      fmt.Sprintf("00000000-0000-0000-0000-%012d", i+10),
				Payload: []byte("policy"),
			})
			results <- err
		}()
	}
	close(start)
	var accepted int
	for range count {
		err := <-results
		if err == nil {
			accepted++
		} else if !errors.Is(err, ErrPending) {
			t.Errorf("unexpected enqueue error: %v", err)
		}
	}
	if accepted != 1 {
		t.Fatalf("accepted %d commands, want exactly one", accepted)
	}
}
