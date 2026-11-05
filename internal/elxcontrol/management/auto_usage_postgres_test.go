package management

import (
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/ElXnet/ElX-control/internal/elxcontrol/journal"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/policytransport"
	"github.com/google/uuid"
)

func TestAutoProvisionFromCanonicalPolicyManifest(t *testing.T) {
	ctx, db := managementPostgres(t)
	store := SQLStore{DB:db}
	entitlement := uuid.NewString()
	_,err:=db.ExecContext(ctx,`INSERT INTO elx_entitlements
		(id,active_slots,valid_until) VALUES($1,2,clock_timestamp()+interval '1 day')`,entitlement)
	if err!=nil{t.Fatal(err)}
	_,err=db.ExecContext(ctx,`INSERT INTO elx_rate_budgets
		(entitlement_id,up_limit,down_limit) VALUES($1,10000,10000)`,entitlement)
	if err!=nil{t.Fatal(err)}
	schedule:=ScheduleSpec{ScheduleID:uuid.NewString(),Cadence:"day",Timezone:"UTC",
		Direction:"total",ThresholdBytes:100000,ReducedUp:100,ReducedDown:100}
	created,err:=store.CreateSchedule(ctx,entitlement,schedule)
	if err!=nil{t.Fatal(err)}
	if created.PeriodID==""{t.Fatal("no schedule period")}
	var policy []policytransport.Binding
	boots:=make(map[string]uuid.UUID)
	for i:=0;i<2;i++{
		node,resource,incarnation:=uuid.New(),uuid.New(),uuid.New()
		pub,_,err:=ed25519.GenerateKey(nil)
		if err!=nil{t.Fatal(err)}
		boots[node.String()]=incarnation
		_,err=db.ExecContext(ctx,`INSERT INTO elx_operation_targets(node_id,resource_id)
			VALUES($1,$2)`,node,resource)
		if err!=nil{t.Fatal(err)}
		_,err=db.ExecContext(ctx,`INSERT INTO elx_rate_grants
			(entitlement_id,node_id,resource_id,committed_up,committed_down,epoch,barrier_public_key)
			VALUES($1,$2,$3,500,500,1,$4)`,entitlement,node,resource,[]byte(pub))
		if err!=nil{t.Fatal(err)}
		_,err=db.ExecContext(ctx,`INSERT INTO elx_core_identities(node_id,incarnation,public_key)
			VALUES($1,$2,$3)`,node,incarnation,[]byte(pub))
		if err!=nil{t.Fatal(err)}
		policy=append(policy,policytransport.Binding{
			Target:journal.Target{NodeID:node.String(),ResourceID:resource.String()},
			Subscription:"vless-profile-"+node.String(),Epoch:1,PublicKey:pub,
		})
	}
	// One omitted grant cannot be silently treated as fully accounted.
	if _,err=store.AutoProvisionFromBindings(ctx,entitlement,schedule.ScheduleID,policy[:1]);
		!errors.Is(err,journal.ErrConflict){t.Fatalf("partial manifest accepted: %v",err)}
	var num int
	if err=db.QueryRowContext(ctx,"SELECT count(*) FROM elx_accounting_assignments").Scan(&num);err!=nil{t.Fatal(err)}
	if num!=0{t.Fatalf("partial manifest wrote %d streams",num)}

	wrong:=append([]policytransport.Binding(nil),policy...)
	wrong[0].Epoch=2
	if _,err=store.AutoProvisionFromBindings(ctx,entitlement,schedule.ScheduleID,wrong);
		!errors.Is(err,journal.ErrConflict){t.Fatalf("wrong rate epoch accepted: %v",err)}
	badKey,_,err:=ed25519.GenerateKey(nil)
	if err!=nil{t.Fatal(err)}
	wrong=append([]policytransport.Binding(nil),policy...)
	wrong[0].PublicKey=badKey
	if _,err=store.AutoProvisionFromBindings(ctx,entitlement,schedule.ScheduleID,wrong);
		!errors.Is(err,journal.ErrConflict){t.Fatalf("substituted core key accepted: %v",err)}

	first,err:=store.AutoProvisionFromBindings(ctx,entitlement,schedule.ScheduleID,policy)
	if err!=nil||len(first)!=2{t.Fatalf("automatic two-node enrollment: %d %v",len(first),err)}
	for _,item:=range first {
		node:=item.Binding.NodeID.String()
		var expected *policytransport.Binding
		for i:=range policy {
			if policy[i].Target.NodeID==node {expected=&policy[i];break}
		}
		if expected==nil || item.AlreadyExisted || item.Primed ||
			item.Binding.Incarnation!=boots[node] ||
			item.ResourceID.String()!=expected.Target.ResourceID ||
			item.SubscriptionID!=expected.Subscription ||
			item.Binding.Generation!=expected.Epoch {
			t.Fatalf("incorrect signed assignment for node %s: %+v",node,item)
		}
	}
	again,err:=store.AutoProvisionFromBindings(ctx,entitlement,schedule.ScheduleID,policy)
	if err!=nil||len(again)!=2{t.Fatalf("idempotent re-enrollment: %v",err)}
	for i:=range again {
		if !again[i].AlreadyExisted||first[i].Binding!=again[i].Binding{
			t.Fatalf("unstable source identity: %+v vs %+v",first[i],again[i])
		}
	}
	// Changing the policy's subscription cannot steal an already provisioned
	// rate grant even if the core signing key is unchanged.
	wrong=append([]policytransport.Binding(nil),policy...)
	wrong[0].Subscription="a-different-vless-profile"
	if _,err=store.AutoProvisionFromBindings(ctx,entitlement,schedule.ScheduleID,wrong);
		!errors.Is(err,journal.ErrConflict){t.Fatalf("subscription remap accepted: %v",err)}

	// Replacing a core after restart needs explicit recovery. Old assignments
	// cannot be quietly recycled or misinterpreted as the new incarnation.
	freshBoot:=uuid.New()
	_,err=db.ExecContext(ctx,`INSERT INTO elx_core_identities(node_id,incarnation,public_key)
		VALUES($1,$2,$3)`,policy[0].Target.NodeID,freshBoot,[]byte(policy[0].PublicKey))
	if err!=nil{t.Fatal(err)}
	if _,err=store.AutoProvisionFromBindings(ctx,entitlement,schedule.ScheduleID,policy);
		!errors.Is(err,journal.ErrConflict){t.Fatalf("ambiguous core boot accepted: %v",err)}
	_,err=db.ExecContext(ctx,`UPDATE elx_core_identities SET revoked=true
		WHERE node_id=$1 AND incarnation=$2`,policy[0].Target.NodeID,boots[policy[0].Target.NodeID])
	if err!=nil{t.Fatal(err)}
	if _,err=store.AutoProvisionFromBindings(ctx,entitlement,schedule.ScheduleID,policy);
		!errors.Is(err,journal.ErrConflict){t.Fatalf("old incarnation was silently rebound: %v",err)}
}
