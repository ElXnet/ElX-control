package management

import (
 "context"
 "crypto/ed25519"
 "errors"
 "testing"
 "time"

 "github.com/ElXnet/ElX-control/internal/elxcontrol/accounting"
 "github.com/ElXnet/ElX-control/internal/elxcontrol/corepolicy"
 "github.com/ElXnet/ElX-control/internal/elxcontrol/journal"
 "github.com/google/uuid"
)

func TestStagedFUPDoesNotInterruptVPNUntilSignedActivation(t *testing.T) {
 ctx,db:=managementPostgres(t)
 store:=SQLStore{DB:db}
 e,node,res,boot,execID,stream:=uuid.New(),uuid.New(),uuid.New(),uuid.New(),uuid.New(),uuid.New()
	key,_,err:=ed25519.GenerateKey(nil)
	if err!=nil{t.Fatal(err)}
	if _,err=db.ExecContext(ctx,`INSERT INTO elx_entitlements(id,active_slots,valid_until)
 VALUES($1,2,clock_timestamp()+interval '1 day')`,e);err!=nil{t.Fatal(err)}
	if _,err=db.ExecContext(ctx,`INSERT INTO elx_rate_budgets(entitlement_id,up_limit,down_limit)
 VALUES($1,10000,10000)`,e);err!=nil{t.Fatal(err)}
	if _,err=db.ExecContext(ctx,`INSERT INTO elx_operation_targets(node_id,resource_id)
 VALUES($1,$2)`,node,res);err!=nil{t.Fatal(err)}
	if _,err=db.ExecContext(ctx,`INSERT INTO elx_rate_grants
 (entitlement_id,node_id,resource_id,committed_up,committed_down,epoch,barrier_public_key)
 VALUES($1,$2,$3,1000,1000,1,$4)`,e,node,res,[]byte(key));err!=nil{t.Fatal(err)}
	if _,err=db.ExecContext(ctx,`INSERT INTO elx_core_identities(node_id,incarnation,public_key)
 VALUES($1,$2,$3)`,node,boot,[]byte(key));err!=nil{t.Fatal(err)}
	spec:=ScheduleSpec{ScheduleID:uuid.NewString(),Cadence:"day",Timezone:"UTC",
	 Direction:"total",ThresholdBytes:100,ReducedUp:100,ReducedDown:100}
	created,err:=store.CreateSchedule(ctx,e.String(),spec)
	if err!=nil{t.Fatal(err)}
	var enabled bool
	if err=db.QueryRowContext(ctx,"SELECT enabled FROM elx_period_schedules WHERE id=$1",spec.ScheduleID).Scan(&enabled);err!=nil{t.Fatal(err)}
	if enabled{t.Fatal("new customer FUP immediately interrupted an unprovisioned VPN")}
	if _,err=db.ExecContext(ctx,`INSERT INTO elx_fup_events(period_id,reduced_up,reduced_down)
		VALUES($1,100,100)`,created.PeriodID);err!=nil{t.Fatal(err)}
	queued,err:=journal.ReconcileFUP(ctx,db,e.String())
	if err!=nil||queued.Active||queued.Queued!=0{
		t.Fatalf("staged FUP changed rate budget: %+v %v",queued,err)
	}
	// Before activation, missing accounting is NOT a lease refusal.
	ready,err:=journal.SignedFUPLeaseReady(ctx,db,e.String(),node.String(),res.String(),"lab")
	if err!=nil||!ready{t.Fatalf("staged FUP rejected valid VPN lease: %v %v",ready,err)}
	if _,err=store.ActivateSchedule(ctx,e.String(),spec.ScheduleID);!errors.Is(err,ErrNotReady){
	 t.Fatalf("unprovisioned FUP became active: %v",err)
	}
	provision:=UsageProvision{ScheduleID:spec.ScheduleID,NodeID:node.String(),
	 ResourceID:res.String(),ExecutorID:execID.String(),Incarnation:boot.String(),
	 AccountingID:stream.String(),Generation:1,SubscriptionID:"lab"}
	if _,err=store.ProvisionUsageStream(ctx,e.String(),provision);err!=nil{t.Fatal(err)}
	if _,err=store.ActivateSchedule(ctx,e.String(),spec.ScheduleID);!errors.Is(err,ErrNotReady){
	 t.Fatalf("unprimed FUP became active: %v",err)
	}
	// A signed usage baseline is accepted during staging. Only the trusted
	// server may activate the schedule after this stage.
	now:=time.Now().UTC()
	assignment:=accounting.Assignment{NodeID:node,ExecutorID:execID,Incarnation:boot,
	 AccountingID:stream,Generation:1}
	r:=provisionUsageReader{name:"lab",key:key,value:corepolicy.Usage{
	 Incarnation:boot,Sequence:1,SampledAt:now,UpBytes:1500,DownBytes:900}}
	receipt,err:=accounting.CollectCurrent(ctx,db,node,uuid.MustParse(spec.ScheduleID),assignment,r)
	if err!=nil||receipt.Crossed{t.Fatalf("staging baseline: %+v %v",receipt,err)}
	active,err:=store.ActivateSchedule(ctx,e.String(),spec.ScheduleID)
	if err!=nil||!active.Enabled||!active.Coverage.Ready{t.Fatalf("cannot activate ready FUP: %+v %v",active,err)}
	queued,err=journal.ReconcileFUP(ctx,db,e.String())
	if err!=nil||!queued.Active||queued.Queued!=1{
		t.Fatalf("verified activated FUP did not queue reduction: %+v %v",queued,err)
	}
	again,err:=store.ActivateSchedule(ctx,e.String(),spec.ScheduleID)
	if err!=nil||!again.AlreadyEnabled{t.Fatalf("activation replay: %+v %v",again,err)}
	ready,err=journal.SignedFUPLeaseReady(ctx,db,e.String(),node.String(),res.String(),"lab")
	if err!=nil||!ready{t.Fatalf("fresh FUP denied legitimate lease: %v %v",ready,err)}
	ready,err=journal.SignedFUPLeaseReady(ctx,db,e.String(),node.String(),res.String(),"another")
	if err!=nil||ready{t.Fatalf("wrong subscription got signed lease: %v %v",ready,err)}
	if _,err=db.ExecContext(ctx,`UPDATE elx_accounting_streams SET last_received_at=clock_timestamp()-interval '2 minutes'
 WHERE accounting_id=$1`,stream);err!=nil{t.Fatal(err)}
	ready,err=journal.SignedFUPLeaseReady(ctx,db,e.String(),node.String(),res.String(),"lab")
	if err!=nil||ready{t.Fatalf("expired source still renewed VPN lease: %v %v",ready,err)}
	r.value.Sequence=2
	r.value.UpBytes+=100
	r.value.DownBytes+=100
	if _,err=accounting.CollectCurrent(context.Background(),db,node,uuid.MustParse(spec.ScheduleID),assignment,r);err!=nil{t.Fatal(err)}
	ready,err=journal.SignedFUPLeaseReady(ctx,db,e.String(),node.String(),res.String(),"lab")
	if err!=nil||!ready{t.Fatalf("new trusted readback did not restore lease: %v %v",ready,err)}
}
