package journal

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/accounting"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/corepolicy"
)

type signedUsageStub struct {
	id          string
	key         ed25519.PublicKey
	usage       corepolicy.Usage
}

func (s signedUsageStub) ReadUsage(_ context.Context, id string, key ed25519.PublicKey) (corepolicy.Usage, error) {
	if id != s.id || !bytes.Equal(key, s.key) {
		return corepolicy.Usage{}, errors.New("incorrect pinned identity or subscription")
	}
	return s.usage, nil
}

func TestCollectPinnedCoreUsageAcrossTwoNodes(t *testing.T) {
	ctx, db := testDatabase(t)
	entitlement, period := uuid.New(), uuid.New()
	now := time.Now().UTC().Truncate(time.Second)
	_, err := db.ExecContext(ctx, `INSERT INTO elx_entitlements(id,active_slots,valid_until)
		VALUES($1,2,clock_timestamp()+interval '1 day')`, entitlement)
	checkError(t, err, nil)
	_, err = db.ExecContext(ctx, `INSERT INTO elx_rate_budgets
		(entitlement_id,up_limit,down_limit) VALUES($1,100,100)`, entitlement)
	checkError(t, err, nil)
	_, err = db.ExecContext(ctx, `INSERT INTO elx_usage_periods
		(id,entitlement_id,starts_at,ends_at,direction,threshold_bytes,reduced_up,reduced_down)
		VALUES($1,$2,$3,$4,'total',100,10,10)`, period, entitlement, now.Add(-time.Hour), now.Add(time.Hour))
	checkError(t, err, nil)
	type source struct {
		binding accounting.Assignment
		key     ed25519.PublicKey
		name    string
		usage   corepolicy.Usage
	}
	var nodes [2]source
	for i := range nodes {
		binding := accounting.Assignment{NodeID: uuid.New(), ExecutorID: uuid.New(),
			Incarnation: uuid.New(), AccountingID: uuid.New(), Generation: 1, PeriodID: period}
		key, _, err := ed25519.GenerateKey(nil)
		checkError(t, err, nil)
		sub := uuid.NewString()
		_, err = db.ExecContext(ctx, `INSERT INTO elx_core_identities(node_id,incarnation,public_key)
			VALUES($1,$2,$3)`, binding.NodeID, binding.Incarnation, []byte(key))
		checkError(t, err, nil)
		_, err = db.ExecContext(ctx, `INSERT INTO elx_accounting_streams
			(node_id,executor_id,incarnation,accounting_id,generation,period_id)
			VALUES($1,$2,$3,$4,$5,$6)`,
			binding.NodeID, binding.ExecutorID, binding.Incarnation, binding.AccountingID,
			binding.Generation, period)
		checkError(t, err, nil)
		_, err = db.ExecContext(ctx, `INSERT INTO elx_accounting_assignments
			(node_id,executor_id,incarnation,accounting_id,generation,period_id,subscription_id)
			VALUES($1,$2,$3,$4,$5,$6,$7)`,
			binding.NodeID, binding.ExecutorID, binding.Incarnation, binding.AccountingID,
			binding.Generation, period, sub)
		checkError(t, err, nil)
		nodes[i] = source{binding: binding, key: key, name: sub,
			usage: corepolicy.Usage{Incarnation: binding.Incarnation, Sequence: 1,
				SampledAt: now, UpBytes: int64(20+15*i), DownBytes: int64(20+15*i)}}
		targetResource := uuid.New()
		_, err = db.ExecContext(ctx, `INSERT INTO elx_operation_targets(node_id,resource_id)
			VALUES($1,$2)`, binding.NodeID, targetResource)
		checkError(t, err, nil)
		_, err = db.ExecContext(ctx, `INSERT INTO elx_rate_grants
			(entitlement_id,node_id,resource_id,committed_up,committed_down,epoch,barrier_public_key)
			VALUES($1,$2,$3,40,40,1,$4)`,
			entitlement, binding.NodeID, targetResource, []byte(key))
		checkError(t, err, nil)
	}

	read := func(s source) (accounting.Receipt, error) {
		return accounting.Collect(ctx, db, s.binding.NodeID, s.binding,
			signedUsageStub{s.name, s.key, s.usage})
	}
	first, err := read(nodes[0])
	checkError(t, err, nil)
	if first.Crossed || first.Duplicate || first.Sequence != 1 {
		t.Fatalf("unexpected first receipt: %+v", first)
	}
	second, err := read(nodes[1])
	checkError(t, err, nil)
	if !second.Crossed || second.Duplicate {
		t.Fatalf("two-node FUP did not cross threshold: %+v", second)
	}
	// The crossing must feed the durable rate-grant outbox for both nodes,
	// rather than merely updating the dashboard's usage counter.
	queued, err := ReconcileFUP(ctx, db, entitlement.String())
	checkError(t, err, nil)
	if !queued.Active || queued.Queued != 2 {
		t.Fatalf("signed FUP crossing did not enqueue two node reductions: %+v", queued)
	}
	repeated, err := ReconcileFUP(ctx, db, entitlement.String())
	checkError(t, err, nil)
	if repeated.Queued != 0 || repeated.Pending != 2 {
		t.Fatalf("retry duplicated pending reductions: %+v", repeated)
	}
	replay, err := read(nodes[0])
	checkError(t, err, nil)
	if !replay.Duplicate || replay.Crossed {
		t.Fatalf("duplicate sample charged again: %+v", replay)
	}
	mismatched := nodes[0]
	mismatched.usage.Incarnation = uuid.New()
	_, err = read(mismatched)
	checkError(t, err, accounting.ErrStream)
	_, err = accounting.Collect(ctx, db, nodes[1].binding.NodeID, nodes[0].binding,
		signedUsageStub{nodes[0].name, nodes[0].key, nodes[0].usage})
	checkError(t, err, accounting.ErrSample)
	badStream := nodes[0]
	badStream.binding.Generation++
	_, err = read(badStream)
	checkError(t, err, accounting.ErrStream)
	badKey := nodes[0]
	badKey.key = nodes[1].key
	if _, err = read(badKey); err == nil {
		t.Fatal("collector accepted a substitute signing key")
	}
	nodes[0].usage.Sequence = 2
	nodes[0].usage.UpBytes += 10
	added, err := read(nodes[0])
	checkError(t, err, nil)
	if added.Crossed || added.Duplicate {
		t.Fatalf("incremental sample not applied: %+v", added)
	}
	_, err = db.ExecContext(ctx, `UPDATE elx_core_identities SET revoked=true
		WHERE node_id=$1 AND incarnation=$2`, nodes[0].binding.NodeID, nodes[0].binding.Incarnation)
	checkError(t, err, nil)
	nodes[0].usage.Sequence = 3
	nodes[0].usage.UpBytes += 10
	_, err = read(nodes[0])
	checkError(t, err, accounting.ErrStream)
	var up, down, events int64
	err = db.QueryRowContext(ctx, `SELECT up_bytes,down_bytes FROM elx_usage_periods WHERE id=$1`, period).Scan(&up, &down)
	checkError(t, err, nil)
	err = db.QueryRowContext(ctx, `SELECT count(*) FROM elx_fup_events WHERE period_id=$1`, period).Scan(&events)
	checkError(t, err, nil)
	if up != 65 || down != 55 || events != 1 {
		t.Fatalf("unexpected signed aggregate after replay/revocation: up=%d down=%d events=%d", up, down, events)
	}
}
