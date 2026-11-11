package policytransport

import (
	"context"
	"crypto/sha256"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/ElXnet/ElX-control/internal/elxcontrol/journal"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
)

func TestControlWitnessIncludesTechnicalRetireIntents(t *testing.T) {
	dsn := os.Getenv("ELX_TEST_POSTGRES_DSN")
	if dsn == "" {
		t.Skip("requires disposable ELX_TEST_POSTGRES_DSN")
	}
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil || cfg.Database != "elx_test" ||
		(cfg.Host != "127.0.0.1" && cfg.Host != "::1") {
		t.Fatal("refusing non-disposable PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	admin := stdlib.OpenDB(*cfg)
	defer admin.Close()
	schema := "elx_witness_" + strings.ReplaceAll(uuid.NewString(), "-", "")
	if _, err := admin.ExecContext(ctx, "CREATE SCHEMA "+schema); err != nil { t.Fatal(err) }
	defer func() {
		cleanup, done := context.WithTimeout(context.Background(), 5*time.Second)
		defer done()
		_, _ = admin.ExecContext(cleanup, "DROP SCHEMA "+schema+" CASCADE")
	}()
	cfg.RuntimeParams["search_path"] = schema
	db := stdlib.OpenDB(*cfg)
	defer db.Close()
	if err := journal.Migrate(ctx, db); err != nil { t.Fatal(err) }
	node, resource, executor, profile, entitlement :=
		uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()
	prepare, retire := uuid.NewString(), uuid.NewString()
	hash := sha256.Sum256([]byte("independently reserved technical intent"))
	statements := []struct { query string; args []any }{
		{`INSERT INTO elx_entitlements(id,active_slots,valid_until)
			VALUES($1,2,clock_timestamp()+interval '1 hour')`, []any{entitlement}},
		{`INSERT INTO elx_operation_targets(node_id,resource_id) VALUES($1,$2)`,
			[]any{node,resource}},
		{`INSERT INTO elx_technical_profiles(
			profile_id,node_id,resource_id,executor_id,entitlement_id,
			subscription_id,email,inbound_tag,profile_generation,
			authority_generation,policy_revision,state,operation_id,request_sha256)
			VALUES($1,$2,$3,$4,$5,'lab','x@lab','vless',1,1,1,'prepared',$6,$7)`,
			[]any{profile,node,resource,executor,entitlement,prepare,hash[:]}},
		{`INSERT INTO elx_technical_profile_operations(
			operation_id,profile_id,action,payload_sha256,profile_generation,
			authority_generation,policy_revision,not_before,not_after,state)
			VALUES($1,$2,'prepare',$3,1,1,1,1,60,'INTENT')`,
			[]any{prepare,profile,hash[:]}},
	}
	for _, item := range statements {
		if _, err := db.ExecContext(ctx,item.query,item.args...); err != nil {t.Fatal(err)}
	}
	empty := tombstoneDigestFromEntries(nil)
	read := func() string {
		t.Helper()
		got, err := controlTombstoneDigest(ctx,db,node)
		if err != nil {t.Fatal(err)}
		return got
	}
	if got := read(); got != empty {t.Fatalf("PREPARE changed denial HWM: %s",got)}
	_,err=db.ExecContext(ctx,`INSERT INTO elx_technical_profile_operations(
		operation_id,profile_id,action,payload_sha256,profile_generation,
		authority_generation,policy_revision,not_before,not_after,state)
		VALUES($1,$2,'retire',$3,2,1,1,1,60,'INTENT')`,retire,profile,hash[:])
	if err!=nil {t.Fatal(err)}
	expected:=tombstoneDigestFromEntries([]string{profile+"\n2\n"})
	if got:=read();got!=expected {t.Fatalf("pending signed RETIRE omitted HWM: %s",got)}
	_,err=db.ExecContext(ctx,`UPDATE elx_technical_profile_operations
		SET state='APPLIED',applied_at=clock_timestamp() WHERE operation_id=$1`,retire)
	if err!=nil {t.Fatal(err)}
	_,err=db.ExecContext(ctx,`UPDATE elx_technical_profiles
		SET state='retired' WHERE profile_id=$1`,profile)
	if err!=nil {t.Fatal(err)}
	if got:=read();got!=expected {t.Fatalf("confirmed RETIRE changed HWM: %s",got)}
	foreign,err:=controlTombstoneDigest(ctx,db,uuid.NewString())
	if err!=nil||foreign!=empty {t.Fatalf("foreign node inherited denial: %s %v",foreign,err)}
}
