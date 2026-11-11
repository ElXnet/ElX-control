package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"maps"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ElXnet/ElX-control/internal/elxcontrol/journal"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func technicalAuditTestDatabase(t *testing.T) (context.Context, *sql.DB, *sql.DB) {
	t.Helper()
	dsn := os.Getenv("ELX_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("ELX_TEST_POSTGRES_DSN required for PostgreSQL acceptance")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Database != "elx_test" || (cfg.Host != "127.0.0.1" && cfg.Host != "::1") {
		t.Fatal("refusing non-disposable technical audit PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
	t.Cleanup(cancel)
	admin := stdlib.OpenDB(*cfg)
	t.Cleanup(func() { _ = admin.Close() })
	schema := "elx_test_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_, _ = admin.ExecContext(c, "DROP SCHEMA "+schema+" CASCADE")
	})
	cfg.RuntimeParams = maps.Clone(cfg.RuntimeParams)
	cfg.RuntimeParams["search_path"] = schema
	rw := stdlib.OpenDB(*cfg)
	t.Cleanup(func() { _ = rw.Close() })
	if err := journal.Migrate(ctx, rw); err != nil {
		t.Fatal(err)
	}
	cfg.RuntimeParams = maps.Clone(cfg.RuntimeParams)
	cfg.RuntimeParams["default_transaction_read_only"] = "on"
	ro := stdlib.OpenDB(*cfg)
	t.Cleanup(func() { _ = ro.Close() })
	return ctx, rw, ro
}

func seedTechnicalAuditOperation(t *testing.T, ctx context.Context, db *sql.DB,
	entitlement, node, resource, executor, action, phase, state string,
	before, after int64,
) string {
	t.Helper()
	id, op := uuid.NewString(), uuid.NewString()
	fingerprint := sha256.Sum256([]byte(id + "/" + op))
	queryProfile := "INSERT INTO elx_technical_profiles(" +
		"profile_id,node_id,resource_id,executor_id,entitlement_id," +
		"subscription_id,email,inbound_tag,profile_generation," +
		"authority_generation,policy_revision,state,operation_id,request_sha256" +
		") VALUES($1,$2,$3,$4,$5,'lab',$6,'vless-test',1,1,1,$7,$8,$9)"
	if _, err := db.ExecContext(ctx, queryProfile,
		id, node, resource, executor, entitlement,
		"user-"+id+"@invalid.test", phase, op, fingerprint[:]); err != nil {
		t.Fatal(err)
	}
	var appliedAt any
	if state == "APPLIED" {
		appliedAt = time.Now().UTC()
	}
	queryOperation := "INSERT INTO elx_technical_profile_operations(" +
		"operation_id,profile_id,action,payload_sha256,profile_generation," +
		"authority_generation,policy_revision,not_before,not_after,state,applied_at" +
		") VALUES($1,$2,$3,$4,1,1,1,$5,$6,$7,$8)"
	if _, err := db.ExecContext(ctx, queryOperation,
		op, id, action, fingerprint[:], before, after, state, appliedAt); err != nil {
		t.Fatal(err)
	}
	return op
}

func TestTechnicalRecoveryAuditPostgresReadOnlyAndBounded(t *testing.T) {
	ctx, rw, ro := technicalAuditTestDatabase(t)
	node, otherNode, resource, executor, entitlement := uuid.NewString(),
		uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	exec := func(query string, args ...any) {
		t.Helper()
		if _, err := rw.ExecContext(ctx, query, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec("INSERT INTO elx_entitlements(id,active_slots,valid_until) "+
		"VALUES($1,1,clock_timestamp()+interval '1 hour')", entitlement)
	for _, n := range []string{node, otherNode} {
		exec("INSERT INTO elx_operation_targets(node_id,resource_id) "+
			"VALUES($1,$2)", n, resource)
	}
	now := time.Now().UTC().Unix()
	expiredPrepare := seedTechnicalAuditOperation(t, ctx, rw, entitlement,
		node, resource, executor, "prepare", "prepared", "INTENT",
		now-40, now-10)
	futureInstall := seedTechnicalAuditOperation(t, ctx, rw, entitlement,
		node, resource, executor, "install", "prepared", "INTENT",
		now+10, now+40)
	_ = seedTechnicalAuditOperation(t, ctx, rw, entitlement,
		otherNode, resource, executor, "retire", "retiring", "INTENT",
		now-40, now-10)
	_ = seedTechnicalAuditOperation(t, ctx, rw, entitlement,
		node, resource, executor, "install", "installed", "APPLIED",
		now-40, now-10)

	var out bytes.Buffer
	if err := inspectTechnicalRecoveryTo(ctx, ro, []string{node}, &out); err != nil {
		t.Fatalf("read-only PostgreSQL technical audit failed: %v", err)
	}
	var report TechnicalRecoveryAudit
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		t.Fatal(err)
	}
	if report.NodeID != node || report.AuthorizedMutation || len(report.Pending) != 2 {
		t.Fatalf("audit exposed foreign/APPLIED operation or granted mutation: %+v", report)
	}
	observed := make(map[string]TechnicalRecoveryAuditRow, 2)
	for _, row := range report.Pending {
		observed[row.OperationID] = row
	}
	if !observed[expiredPrepare].Expired ||
		observed[expiredPrepare].NextStep != "manual_prepare_review" ||
		observed[futureInstall].Expired ||
		observed[futureInstall].NextStep != "await_signed_delivery" {
		t.Fatalf("technical audit wrongly recommended a mutation: %+v", report.Pending)
	}
	if strings.Contains(out.String(), "user-") ||
		strings.Contains(out.String(), "requestSha256") ||
		strings.Contains(out.String(), "signature") {
		t.Fatal("forensic audit leaked technical user, grant hash or signature")
	}
	var stillPending int
	queryCount := "SELECT count(*) FROM elx_technical_profile_operations " +
		"WHERE state='INTENT' AND operation_id IN ($1,$2)"
	if err := rw.QueryRowContext(ctx, queryCount,
		expiredPrepare, futureInstall).Scan(&stillPending); err != nil || stillPending != 2 {
		t.Fatalf("read-only command changed Control's signed intents: %d %v", stillPending, err)
	}
	out.Reset()
	if err := inspectTechnicalRecoveryTo(ctx, ro, []string{otherNode}, &out); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(out.String(), expiredPrepare) ||
		strings.Contains(out.String(), futureInstall) {
		t.Fatal("node-scoped audit crossed the independently pinned node boundary")
	}

	// Reject a silently truncated backlog (SQL LIMIT 129, JSON limit 128).
	// No partial JSON can escape after overflow.
	for range 127 {
		seedTechnicalAuditOperation(t, ctx, rw, entitlement,
			node, resource, executor, "prepare", "prepared", "INTENT",
			now-40, now-10)
	}
	out.Reset()
	err := inspectTechnicalRecoveryTo(ctx, ro, []string{node}, &out)
	if err == nil || !strings.Contains(err.Error(), "too many unresolved") ||
		out.Len() != 0 {
		t.Fatalf("backlog overflow was silently truncated or emitted partial JSON: %v", err)
	}
}

func TestTechnicalRecoveryAuditWrongNodeFailsBeforeDatabase(t *testing.T) {
	var out bytes.Buffer
	for _, args := range [][]string{
		nil, {"not-a-uuid"}, {uuid.Nil.String()}, {uuid.NewString(), uuid.NewString()},
	} {
		err := inspectTechnicalRecoveryTo(context.Background(), &sql.DB{}, args, &out)
		if err == nil {
			t.Fatalf("invalid technical recovery selector %v accepted", args)
		}
	}
	if out.Len() != 0 {
		t.Fatal("rejected technical recovery selector unexpectedly printed data")
	}
}
