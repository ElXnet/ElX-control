package management

import (
	"bytes"
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

type provisionUsageReader struct {
	name string
	key  ed25519.PublicKey
	value corepolicy.Usage
}
func (r provisionUsageReader) ReadUsage(_ context.Context,name string,key ed25519.PublicKey)(corepolicy.Usage,error){
	if name!=r.name || !bytes.Equal(r.key,key){return corepolicy.Usage{},errors.New("wrong pinned usage identity")}
	return r.value,nil
}

func TestProvisionUsageTrustBoundaryAndSignedBaseline(t *testing.T){
	ctx,db:=managementPostgres(t)
	entitlement:=uuid.New()
	foreign:=uuid.New()
	node:=uuid.New()
	resource:=uuid.New()
	executor:=uuid.New()
	incarnation:=uuid.New()
	accountingID:=uuid.New()
	schedule:=uuid.New()
	period:=uuid.New()
	otherNode:=uuid.New()
	public,_,err:=ed25519.GenerateKey(nil)
	if err!=nil{t.Fatal(err)}
	for _,id:=range []uuid.UUID{entitlement,foreign}{
		if _,err=db.ExecContext(ctx,`INSERT INTO elx_entitlements
			(id,active_slots,valid_until) VALUES($1,2,clock_timestamp()+interval '1 day')`,id);err!=nil{t.Fatal(err)}
	}
	if _,err=db.ExecContext(ctx,`INSERT INTO elx_rate_budgets
		(entitlement_id,up_limit,down_limit) VALUES($1,100000,100000)`,entitlement);err!=nil{t.Fatal(err)}
	now:=time.Now().UTC()
	if _,err=db.ExecContext(ctx,`INSERT INTO elx_usage_periods
		(id,entitlement_id,starts_at,ends_at,direction,threshold_bytes,reduced_up,reduced_down)
		VALUES($1,$2,$3,$4,'total',100,100,100)`,
		period,entitlement,now.Add(-time.Hour),now.Add(time.Hour));err!=nil{t.Fatal(err)}
	if _,err=db.ExecContext(ctx,`INSERT INTO elx_period_schedules
		(id,entitlement_id,cadence,timezone_name,current_period_id)
		VALUES($1,$2,'day','UTC',$3)`,schedule,entitlement,period);err!=nil{t.Fatal(err)}
	if _,err=db.ExecContext(ctx,`UPDATE elx_usage_periods SET schedule_id=$2 WHERE id=$1`,period,schedule);err!=nil{t.Fatal(err)}
	if _,err=db.ExecContext(ctx,`INSERT INTO elx_core_identities
		(node_id,incarnation,public_key) VALUES($1,$2,$3)`,node,incarnation,[]byte(public));err!=nil{t.Fatal(err)}
	if _,err=db.ExecContext(ctx,`INSERT INTO elx_operation_targets(node_id,resource_id) VALUES($1,$2)`,node,resource);err!=nil{t.Fatal(err)}
	if _,err=db.ExecContext(ctx,`INSERT INTO elx_rate_grants
		(entitlement_id,node_id,resource_id,committed_up,committed_down,epoch,barrier_public_key)
		VALUES($1,$2,$3,1000,1000,1,$4)`,entitlement,node,resource,[]byte(public));err!=nil{t.Fatal(err)}

	store:=SQLStore{DB:db}
	spec:=UsageProvision{
		ScheduleID:schedule.String(),NodeID:node.String(),
		ResourceID:resource.String(),ExecutorID:executor.String(),
		Incarnation:incarnation.String(),AccountingID:accountingID.String(),
		Generation:1,SubscriptionID:"trusted-vless-subscription",
	}
	if _,err=store.ProvisionUsageStream(ctx,foreign.String(),spec);!errors.Is(err,ErrSchedule){
		t.Fatalf("foreign entitlement permitted: %v",err)
	}
	invalid:=spec;invalid.NodeID=otherNode.String()
	if _,err=store.ProvisionUsageStream(ctx,entitlement.String(),invalid);!errors.Is(err,journal.ErrConflict){
		t.Fatalf("unregistered grant/core accepted: %v",err)
	}
	missing:=spec;missing.AccountingID=uuid.Nil.String()
	if _,err=store.ProvisionUsageStream(ctx,entitlement.String(),missing);!errors.Is(err,journal.ErrInvalid){
		t.Fatalf("zero stream UUID accepted: %v",err)
	}
	provisioned,err:=store.ProvisionUsageStream(ctx,entitlement.String(),spec)
	if err!=nil||provisioned.Primed||provisioned.AlreadyExisted||provisioned.PeriodID!=period{
		t.Fatalf("new usage assignment: %+v %v",provisioned,err)
	}
	again,err:=store.ProvisionUsageStream(ctx,entitlement.String(),spec)
	if err!=nil||!again.AlreadyExisted||again.Primed{t.Fatalf("replay: %+v %v",again,err)}
	conflict:=spec;conflict.SubscriptionID="other-vless-subscription"
	if _,err=store.ProvisionUsageStream(ctx,entitlement.String(),conflict);!errors.Is(err,journal.ErrConflict){
		t.Fatalf("replacement without signed drain accepted: %v",err)
	}
	conflict=spec;conflict.AccountingID=uuid.NewString()
	if _,err=store.ProvisionUsageStream(ctx,entitlement.String(),conflict);!errors.Is(err,journal.ErrConflict){
		t.Fatalf("duplicate rate grant assigned to two streams: %v",err)
	}

	coverage,err:=store.UsageCoverage(ctx,entitlement.String(),schedule.String())
	if err!=nil||coverage.Ready||coverage.ExpectedGrants!=1||coverage.AssignedGrants!=1||coverage.PrimedGrants!=0{
		t.Fatalf("premature FUP readiness: %+v %v",coverage,err)
	}
	reader:=provisionUsageReader{name:spec.SubscriptionID,key:public,
		value:corepolicy.Usage{Incarnation:incarnation,Sequence:1,SampledAt:now,UpBytes:5000,DownBytes:8000}}
	b:=accounting.Assignment{
		NodeID:node,ExecutorID:executor,Incarnation:incarnation,
		AccountingID:accountingID,Generation:1,
	}
	prime,err:=accounting.CollectCurrent(ctx,db,node,schedule,b,reader)
	if err!=nil||prime.Crossed||prime.Duplicate||prime.Sequence!=1{t.Fatalf("prime result: %+v %v",prime,err)}
	var periodUp,periodDown int64
	if err=db.QueryRowContext(ctx,`SELECT up_bytes,down_bytes FROM elx_usage_periods WHERE id=$1`,period).Scan(&periodUp,&periodDown);err!=nil{t.Fatal(err)}
	if periodUp!=0||periodDown!=0{t.Fatalf("historical traffic charged to new period: %d/%d",periodUp,periodDown)}
	coverage,err=store.UsageCoverage(ctx,entitlement.String(),schedule.String())
	if err!=nil||!coverage.Ready||coverage.PrimedGrants!=1{t.Fatalf("trusted baseline not recognized: %+v %v",coverage,err)}
	// An agent that stopped sending new signed sequences is never healthy.
	if _,err=db.ExecContext(ctx,`UPDATE elx_accounting_streams
		SET last_received_at=clock_timestamp()-interval '2 minutes'
		WHERE period_id=$1`,period);err!=nil{t.Fatal(err)}
	coverage,err=store.UsageCoverage(ctx,entitlement.String(),schedule.String())
	if err!=nil||coverage.Ready||coverage.FreshGrants!=0 {
		t.Fatalf("stale signed stream marked ready: %+v %v",coverage,err)
	}
	dup,err:=accounting.CollectCurrent(ctx,db,node,schedule,b,reader)
	if err!=nil||!dup.Duplicate||dup.Crossed{t.Fatalf("signed replay charged twice: %+v %v",dup,err)}
	coverage,err=store.UsageCoverage(ctx,entitlement.String(),schedule.String())
	if err!=nil||coverage.Ready||coverage.FreshGrants!=0{
		t.Fatalf("replayed signature renewed stale stream: %+v %v",coverage,err)
	}
	reader.value.Sequence=2
	reader.value.UpBytes+=60
	reader.value.DownBytes+=70
	next,err:=accounting.CollectCurrent(ctx,db,node,schedule,b,reader)
	if err!=nil||!next.Crossed{t.Fatalf("signed threshold did not cross: %+v %v",next,err)}
	if err=db.QueryRowContext(ctx,`SELECT up_bytes,down_bytes FROM elx_usage_periods WHERE id=$1`,period).Scan(&periodUp,&periodDown);err!=nil{t.Fatal(err)}
	if periodUp!=60||periodDown!=70{t.Fatalf("increment after baseline wrong: %d/%d",periodUp,periodDown)}
	coverage,err=store.UsageCoverage(ctx,entitlement.String(),schedule.String())
	if err!=nil||!coverage.Ready||coverage.FreshGrants!=1{
		t.Fatalf("new signed sequence did not restore readiness: %+v %v",coverage,err)
	}
	if _,err=db.ExecContext(ctx,`UPDATE elx_core_identities SET revoked=true
		WHERE node_id=$1 AND incarnation=$2`,node,incarnation);err!=nil{t.Fatal(err)}
	coverage,err=store.UsageCoverage(ctx,entitlement.String(),schedule.String())
	if err!=nil||coverage.Ready{t.Fatalf("revoked signing key still marked ready: %+v %v",coverage,err)}
	reader.value.Sequence=3
	reader.value.UpBytes+=1
	if _,err=accounting.CollectCurrent(ctx,db,node,schedule,b,reader);!errors.Is(err,accounting.ErrStream){
		t.Fatalf("revoked core accepted: %v",err)
	}
}

func TestProvisionUsageRejectsMissingGrant(t *testing.T){
	ctx,db:=managementPostgres(t)
	id:=uuid.NewString()
	if _,err:=db.ExecContext(ctx,`INSERT INTO elx_entitlements
	(id,active_slots,valid_until) VALUES($1,2,clock_timestamp()+interval '1 day')`,id);err!=nil{t.Fatal(err)}
	// Even an existing entitlement cannot authorize source enrollment
	// without a purchased rate grant, current FUP schedule and pinned core.
	_,err:=(SQLStore{DB:db}).ProvisionUsageStream(ctx,id,UsageProvision{
		ScheduleID:uuid.NewString(),NodeID:uuid.NewString(),ResourceID:uuid.NewString(),
		ExecutorID:uuid.NewString(),Incarnation:uuid.NewString(),
		AccountingID:uuid.NewString(),Generation:1,SubscriptionID:"lab",
	})
	if !errors.Is(err,ErrSchedule){t.Fatalf("unprovisioned usage accepted: %v",err)}
}
