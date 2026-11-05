package journal

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestSchedulerLeaderFencesFormerOwnerAndExpiredToken(t *testing.T) {
	ctx,db:=testDatabase(t)
	entitlement,_,_:=seedDemandRates(t,ctx,db,Rate{100,100},Rate{50,50})
	a,b:=uuid.New(),uuid.New()
	first,err:=AcquireSchedulerLease(ctx,db,entitlement,a,10*time.Second)
	checkError(t,err,nil)
	if first.Epoch!=1 || first.HolderID!=a {t.Fatalf("invalid initial leader: %+v",first)}
	_,err=AcquireSchedulerLease(ctx,db,entitlement,b,10*time.Second)
	if !errors.Is(err,ErrSchedulerBusy){t.Fatalf("stole live leader: %v",err)}
	renewed,err:=RenewSchedulerLease(ctx,db,first,10*time.Second)
	checkError(t,err,nil)
	if renewed.Epoch!=first.Epoch || !renewed.ExpiresAt.After(first.ExpiresAt){
		t.Fatalf("renewal changed epoch or lost expiry: %+v %+v",first,renewed)
	}
	_,err=db.ExecContext(ctx,`UPDATE elx_rate_scheduler_leaders
		SET expires_at=clock_timestamp()-interval '1 second'
		WHERE entitlement_id=$1`,entitlement)
	checkError(t,err,nil)
	_,err=RebalanceAttestedDemand(ctx,db,entitlement,first)
	if !errors.Is(err,ErrSchedulerFenced){t.Fatalf("expired leader queued a move: %v",err)}
	_,err=RenewSchedulerLease(ctx,db,first,10*time.Second)
	if !errors.Is(err,ErrSchedulerFenced){t.Fatalf("expired leader renewed itself: %v",err)}
	second,err:=AcquireSchedulerLease(ctx,db,entitlement,b,10*time.Second)
	checkError(t,err,nil)
	if second.Epoch!=2 || second.HolderID!=b {
		t.Fatalf("takeover did not bump fence epoch: %+v",second)
	}
	_,err=RebalanceAttestedDemand(ctx,db,entitlement,first)
	if !errors.Is(err,ErrSchedulerFenced){t.Fatalf("old epoch authorized action: %v",err)}
	out,err:=RebalanceAttestedDemand(ctx,db,entitlement,second)
	checkError(t,err,nil)
	if out.OperationID!="" || out.Phase!="stable" || out.FrozenTargets!=1 {
		t.Fatalf("leader treated absent evidence as free capacity: %+v",out)
	}
	_,err=db.ExecContext(ctx,`UPDATE elx_rate_scheduler_leaders
		SET expires_at=clock_timestamp()-interval '1 second'
		WHERE entitlement_id=$1`,entitlement)
	checkError(t,err,nil)
	third,err:=AcquireSchedulerLease(ctx,db,entitlement,b,10*time.Second)
	checkError(t,err,nil)
	if third.Epoch!=3{t.Fatalf("same holder reused expired token: %+v",third)}
	_,err=RenewSchedulerLease(ctx,db,second,10*time.Second)
	if !errors.Is(err,ErrSchedulerFenced){t.Fatalf("old token reaccepted: %v",err)}
}

func TestSchedulerConcurrentLeaderElection(t *testing.T) {
	ctx,db:=testDatabase(t)
	db.SetMaxOpenConns(12)
	entitlement,_,_:=seedDemandRates(t,ctx,db,Rate{100,100})
	const workers=8
	begin:=make(chan struct{})
	var wg sync.WaitGroup
	results:=make(chan error,workers)
	for range workers {
		wg.Add(1)
		go func(){
			defer wg.Done()
			<-begin
			_,err:=AcquireSchedulerLease(ctx,db,entitlement,uuid.New(),10*time.Second)
			results<-err
		}()
	}
	close(begin)
	wg.Wait()
	close(results)
	winners:=0
	for err:=range results{
		if err==nil{winners++}else if !errors.Is(err,ErrSchedulerBusy){
			t.Fatalf("election error: %v",err)
		}
	}
	if winners!=1{t.Fatalf("elected %d live leaders",winners)}
}

func seedAttestedRateTarget(t *testing.T, ctx context.Context, db *sql.DB,
	entitlement string, target Target, key ed25519.PublicKey,
	incarnation uuid.UUID, sampledAt time.Time, saturated bool) {
	t.Helper()
	ent,_:=uuid.Parse(entitlement)
	_,err:=db.ExecContext(ctx,`INSERT INTO elx_core_identities
	 (node_id,incarnation,public_key) VALUES($1,$2,$3)`,
		target.NodeID,incarnation,[]byte(key))
	checkError(t,err,nil)
	period,schedule:=uuid.New(),uuid.New()
	_,err=db.ExecContext(ctx,`INSERT INTO elx_usage_periods
	 (id,entitlement_id,starts_at,ends_at,direction,threshold_bytes,reduced_up,reduced_down)
	 VALUES($1,$2,clock_timestamp()-interval '1 hour',
	  clock_timestamp()+interval '1 hour','total',1000000000,100000,100000)`,
		period,ent)
	checkError(t,err,nil)
	_,err=db.ExecContext(ctx,`INSERT INTO elx_period_schedules
	 (id,entitlement_id,cadence,timezone_name,current_period_id,enabled)
	 VALUES($1,$2,'day','UTC',$3,true)`,schedule,ent,period)
	checkError(t,err,nil)
	_,err=db.ExecContext(ctx,`UPDATE elx_usage_periods
	 SET schedule_id=$2 WHERE id=$1`,period,schedule)
	checkError(t,err,nil)
	executor,accountingID:=uuid.New(),uuid.New()
	_,err=db.ExecContext(ctx,`INSERT INTO elx_accounting_streams
	 (node_id,executor_id,incarnation,accounting_id,generation,period_id,
	  primed,last_received_at)
	 VALUES($1,$2,$3,$4,1,$5,true,clock_timestamp())`,
		target.NodeID,executor,incarnation,accountingID,period)
	checkError(t,err,nil)
	_,err=db.ExecContext(ctx,`INSERT INTO elx_accounting_assignments
	 (node_id,executor_id,incarnation,accounting_id,generation,period_id,
	  subscription_id,resource_id)
	 VALUES($1,$2,$3,$4,1,$5,$6,$7)`,
		target.NodeID,executor,incarnation,accountingID,period,
		uuid.NewString(),target.ResourceID)
	checkError(t,err,nil)
	var prevBlocked,currentBlocked int64
	if saturated {prevBlocked,currentBlocked=2,3}
	_,err=db.ExecContext(ctx,`INSERT INTO elx_rate_pressure_samples
	 (node_id,resource_id,incarnation,sequence,sampled_at,received_at,
	  core_revision,policy_up,policy_down,
	  up_bytes,down_bytes,up_blocked_calls,down_blocked_calls,
	  up_blocked_nanos,down_blocked_nanos,up_waiters,down_waiters,
	  previous_sequence,previous_sampled_at,previous_core_revision,
	  previous_policy_up,previous_policy_down,
	  previous_up_bytes,previous_down_bytes,
	  previous_up_blocked_calls,previous_down_blocked_calls,
	  previous_up_blocked_nanos,previous_down_blocked_nanos)
	 VALUES($1,$2,$3,2,$4,clock_timestamp(),
	  1,50000,50000,
	  5000,5000,$5,$5,100,100,0,0,
	  1,$6,1,50000,50000,
	  5000,5000,$7,$7,99,99)`,
		target.NodeID,target.ResourceID,incarnation,sampledAt,
		currentBlocked,sampledAt.Add(-5*time.Second),prevBlocked)
	checkError(t,err,nil)
	_,err=db.ExecContext(ctx,`INSERT INTO elx_rate_lease_acceptances
	 (node_id,resource_id,incarnation,pressure_sequence,
	  lease_sequence,lease_expires_at,policy_revision,
	  policy_up,policy_down,ceiling_up,ceiling_down)
	 VALUES($1,$2,$3,2,42,clock_timestamp()+interval '15 seconds',
	  1,50000,50000,100000,100000)`,
		target.NodeID,target.ResourceID,incarnation)
	checkError(t,err,nil)
}

func TestAttestedSchedulerQueuesReductionFirstAndNeverReusesUnprovedCapacity(t *testing.T) {
	ctx,db:=testDatabase(t)
	entitlement,targets,signer:=seedDemandRates(t,ctx,db,
		Rate{100000,100000},Rate{50000,50000},Rate{50000,50000})
	key:=signer.Public().(ed25519.PublicKey)
	now:=time.Now().UTC().Add(-time.Second)
	seedAttestedRateTarget(t,ctx,db,entitlement,targets[0],key,uuid.New(),now,false)
	seedAttestedRateTarget(t,ctx,db,entitlement,targets[1],key,uuid.New(),now,true)
	leader,err:=AcquireSchedulerLease(ctx,db,entitlement,uuid.New(),15*time.Second)
	checkError(t,err,nil)
	preview,err:=PreviewDemand(ctx,db,entitlement)
	checkError(t,err,nil)
	if len(preview)!=2{t.Fatalf("missing verified pressure/lease: %+v",preview)}
	first,err:=RebalanceAttestedDemand(ctx,db,entitlement,leader)
	checkError(t,err,nil)
	if first.Phase!="lower" || first.Target!=targets[0] ||
		first.Desired!=(Rate{Up:32768,Down:32768}) || first.OperationID=="" {
		t.Fatalf("did not lower signed idle grant first: %+v",first)
	}
	blocked,err:=RebalanceAttestedDemand(ctx,db,entitlement,leader)
	checkError(t,err,nil)
	if blocked.Phase!="waiting" || blocked.OperationID!="" {
		t.Fatalf("raised before barrier: %+v",blocked)
	}
	cmd,err:=Pending(ctx,db,targets[0])
	checkError(t,err,nil)
	// A policy ACK is not a signed lower-rate barrier. Until FinalizeRateMove
	// sees the core's signed proof, no other node can use reclaimed budget.
	checkError(t,ConfirmApplied(ctx,db,targets[0],first.OperationID,1,
		sha256.Sum256(cmd.Payload)),nil)
	checkError(t,FinalizeRateMove(ctx,db,entitlement,targets[0],first.OperationID,nil),ErrRateBarrier)
	proof:=ed25519.Sign(signer,rateBarrierMessage(entitlement,targets[0],
		first.OperationID,1,1,first.Desired))
	checkError(t,FinalizeRateMove(ctx,db,entitlement,targets[0],first.OperationID,proof),nil)
	next,err:=RebalanceAttestedDemand(ctx,db,entitlement,leader)
	checkError(t,err,nil)
	if next.Phase!="raise" || next.Target!=targets[1] ||
		next.Desired!=(Rate{Up:67232,Down:67232}) {
		t.Fatalf("allocator failed to reuse proven released grant: %+v",next)
	}
	var pending int
	checkError(t,db.QueryRowContext(ctx,`SELECT count(*) FROM elx_rate_moves
		WHERE NOT finalized`).Scan(&pending),nil)
	if pending!=1{t.Fatalf("unsafe number of queued journal moves: %d",pending)}
}

func TestAttestedSchedulerRequiresFreshCoreProofAndCurrentBudget(t *testing.T) {
	ctx,db:=testDatabase(t)
	entitlement,targets,signer:=seedDemandRates(t,ctx,db,
		Rate{100000,100000},Rate{50000,50000})
	now:=time.Now().UTC().Add(-time.Second)
	seedAttestedRateTarget(t,ctx,db,entitlement,targets[0],
		signer.Public().(ed25519.PublicKey),uuid.New(),now,true)
	leader,err:=AcquireSchedulerLease(ctx,db,entitlement,uuid.New(),15*time.Second)
	checkError(t,err,nil)
	tests:=[]struct{
		name string
		sql string
	}{
		{"lease expired",`UPDATE elx_rate_lease_acceptances
		 SET lease_expires_at=clock_timestamp()-interval '1 second'`},
		{"different pressure sequence",`UPDATE elx_rate_lease_acceptances SET pressure_sequence=1`},
		{"mismatched pinned key",`UPDATE elx_rate_grants SET barrier_public_key=decode(repeat('00',32),'hex')`},
	}
	for _,test:=range tests {
		t.Run(test.name,func(t *testing.T){
			tx,err:=db.BeginTx(ctx,nil)
			checkError(t,err,nil)
			if _,err=tx.ExecContext(ctx,test.sql);err!=nil{t.Fatal(err)}
			// Query within this transaction proves the read predicate
			// excludes the tampered sample without changing fixtures.
			var count int
			err=tx.QueryRowContext(ctx,`SELECT count(*) FROM elx_rate_pressure_samples p
			 JOIN elx_rate_lease_acceptances l
			  ON l.node_id=p.node_id AND l.resource_id=p.resource_id
			 JOIN elx_rate_grants g
			  ON g.node_id=p.node_id AND g.resource_id=p.resource_id
			 JOIN elx_core_identities c
			  ON c.node_id=p.node_id AND c.incarnation=p.incarnation
			 WHERE l.pressure_sequence=p.sequence
			  AND l.lease_expires_at>clock_timestamp()+interval '2 seconds'
			  AND g.barrier_public_key=c.public_key`).Scan(&count)
			checkError(t,err,nil)
			if count!=0{t.Fatal("untrusted source retained usable proof")}
			checkError(t,tx.Rollback(),nil)
		})
	}
	// A tightened FUP/purchased ceiling is read while the entitlement row
	// is locked, never from a cached offer or stale customer setting.
	_,err=db.ExecContext(ctx,`UPDATE elx_rate_budgets SET up_limit=45000,
		down_limit=45000 WHERE entitlement_id=$1`,entitlement)
	checkError(t,err,nil)
	out,err:=RebalanceAttestedDemand(ctx,db,entitlement,leader)
	checkError(t,err,nil)
	if out.Phase!="lower" || out.Desired.Up>45000 || out.Desired.Down>45000 {
		t.Fatalf("rebalance escaped tightened budget: %+v",out)
	}
}
