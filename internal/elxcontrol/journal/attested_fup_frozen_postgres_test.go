package journal

import (
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/google/uuid"
)

// A newly crossed FUP threshold can make all previous node grants exceed
// the effective budget before the signed agents finish reducing them.
// One node may have stale pressure/lease telemetry at precisely that time.
// The automatic scheduler MUST NOT issue zero-rate disables on any other
// still-live node just because the unknown grant remains conservatively
// reserved. The dedicated FUP reconciler handles all reductions.
func TestAttestedSchedulerWaitsForFUPWhenUnknownCommitmentExceedsBudget(t *testing.T) {
	ctx, db := testDatabase(t)
	entitlement, targets, signer := seedDemandRates(t, ctx, db,
		Rate{100000,100000}, Rate{50000,50000}, Rate{50000,50000})
	now:=time.Now().UTC().Add(-time.Second)
	seedAttestedRateTarget(t,ctx,db,entitlement,targets[0],
		signer.Public().(ed25519.PublicKey),uuid.New(),now,true)
	leader,err:=AcquireSchedulerLease(ctx,db,entitlement,uuid.New(),
		15*time.Second)
	checkError(t,err,nil)
	var period uuid.UUID
	checkError(t,db.QueryRowContext(ctx,`SELECT period_id FROM elx_accounting_streams
		WHERE node_id=$1 LIMIT 1`,targets[0].NodeID).Scan(&period),nil)
	_,err=db.ExecContext(ctx,`UPDATE elx_usage_periods
		SET reduced_up=40000,reduced_down=40000 WHERE id=$1`,period)
	checkError(t,err,nil)
	_,err=db.ExecContext(ctx,`INSERT INTO elx_fup_events(period_id,reduced_up,reduced_down)
		VALUES($1,40000,40000)`,period)
	checkError(t,err,nil)
	// Current grants are 50k+50k, but the event lowers the effective
	// budget to 40k. Target 1 has NO valid lease-attested observation.
	before,err:=PreviewDemand(ctx,db,entitlement)
	checkError(t,err,nil)
	if len(before)!=1 || before[0].Target!=targets[0]{
		t.Fatalf("unexpected verified target set: %+v",before)
	}
	result,err:=RebalanceAttestedDemand(ctx,db,entitlement,leader)
	checkError(t,err,nil)
	if !result.FrozenOverBudget || result.OperationID!="" ||
		result.Phase!="waiting" {
		t.Fatalf("scheduler disabled a live node against frozen FUP budget: %+v",result)
	}
	var pending int
	checkError(t,db.QueryRowContext(ctx,`SELECT count(*) FROM elx_rate_moves
		WHERE NOT finalized`).Scan(&pending),nil)
	if pending!=0 {t.Fatalf("scheduler enqueued %d unsafe rate moves",pending)}

	reduction,err:=ReconcileFUP(ctx,db,entitlement)
	checkError(t,err,nil)
	if !reduction.Active || reduction.Queued!=2 || reduction.Pending!=0{
		t.Fatalf("FUP reconciler failed to own reductions: %+v",reduction)
	}
	rows,err:=db.QueryContext(ctx,`SELECT desired_up,desired_down
		FROM elx_rate_moves WHERE NOT finalized`)
	checkError(t,err,nil)
	count:=0
	for rows.Next(){
		var up,down int64
		if err=rows.Scan(&up,&down);err!=nil{rows.Close();t.Fatal(err)}
		if up!=20000||down!=20000{
			rows.Close()
			t.Fatalf("unsafe FUP target %d/%d",up,down)
		}
		count++
	}
	if err=rows.Err();err!=nil{rows.Close();t.Fatal(err)}
	rows.Close()
	if count!=2 {t.Fatalf("expected two queued signed reductions, got %d",count)}
	// On the next pass the scheduler must not allocate capacity reserved
	// by either unfinished signed barrier.
	again,err:=RebalanceAttestedDemand(ctx,db,entitlement,leader)
	checkError(t,err,nil)
	if again.OperationID!="" || again.Phase!="waiting"{
		t.Fatalf("scheduler raced unfinished FUP barriers: %+v",again)
	}
}
