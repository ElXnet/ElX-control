package journal

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/google/uuid"
)

func TestOperatorQuarantineDoesNotForgeTechnicalAppliedOrReleaseCapacity(t *testing.T) {
	ctx, db := testDatabase(t)
	node, resource, executor, profile, entitlement, store :=
		uuid.NewString(), uuid.NewString(), uuid.NewString(),
		uuid.NewString(), uuid.NewString(), uuid.NewString()
	prepare, install := uuid.NewString(), uuid.NewString()
	evidence := sha256.Sum256([]byte("offline journal and anchored inspector report"))
	digest := sha256.Sum256([]byte("Control signed intent"))

	for _, stmt := range []struct {
		query string
		args  []any
	}{
		{`INSERT INTO elx_entitlements(id,active_slots,valid_until)
			VALUES($1,2,clock_timestamp()+interval '1 hour')`, []any{entitlement}},
		{`INSERT INTO elx_operation_targets(node_id,resource_id) VALUES($1,$2)`,
			[]any{node,resource}},
		{`INSERT INTO elx_rate_budgets(entitlement_id,up_limit,down_limit)
			VALUES($1,250000,250000)`, []any{entitlement}},
		{`INSERT INTO elx_rate_grants(
			entitlement_id,node_id,resource_id,committed_up,committed_down,
			epoch,barrier_public_key) VALUES($1,$2,$3,250000,250000,1,$4)`,
			[]any{entitlement,node,resource,make([]byte,32)}},
		{`INSERT INTO elx_core_store_witnesses(
			node_id,resource_id,executor_id,store_id,authority_generation,core_revision)
			VALUES($1,$2,$3,$4,1,1)`, []any{node,resource,executor,store}},
		{`INSERT INTO elx_technical_profiles(
			profile_id,node_id,resource_id,executor_id,entitlement_id,
			subscription_id,email,inbound_tag,profile_generation,authority_generation,
			policy_revision,state,operation_id,request_sha256)
			VALUES($1,$2,$3,$4,$5,'lab','device@lab','inbound',1,1,1,'prepared',$6,$7)`,
			[]any{profile,node,resource,executor,entitlement,prepare,digest[:]}},
		{`INSERT INTO elx_technical_profile_operations(
			operation_id,profile_id,action,payload_sha256,profile_generation,
			authority_generation,policy_revision,not_before,not_after,state)
			VALUES($1,$2,'prepare',$3,1,1,1,1,60,'INTENT')`,
			[]any{prepare,profile,digest[:]}},
		{`INSERT INTO elx_technical_profile_operations(
			operation_id,profile_id,action,payload_sha256,profile_generation,
			authority_generation,policy_revision,not_before,not_after,state)
			VALUES($1,$2,'install',$3,1,1,1,1,60,'INTENT')`,
			[]any{install,profile,digest[:]}},
	} {
		if _, err := db.ExecContext(ctx, stmt.query, stmt.args...); err != nil {
			t.Fatal(err)
		}
	}
	q := TechnicalNodeQuarantine{
		NodeID: node, ResourceID: resource, ProfileID: profile,
		OperationID: install, StoreID: store, Phase: "INSTALLING",
		EvidenceSHA256: hex.EncodeToString(evidence[:]), OperatorRef: "operator-test",
		ConfirmedNode: node,
	}
	if err := QuarantineTechnicalNode(ctx, db, q); err != nil { t.Fatal(err) }
	if err := QuarantineTechnicalNode(ctx, db, q); err != nil { t.Fatal(err) }
	frozen, err := TechnicalNodeQuarantined(ctx, db, node)
	if err != nil || !frozen { t.Fatalf("quarantine missing: %t %v", frozen, err) }
	foreign, err := TechnicalNodeQuarantined(ctx, db, uuid.NewString())
	if err != nil || foreign { t.Fatalf("foreign node quarantined: %t %v", foreign, err) }
	for _, mutate := range []func(*TechnicalNodeQuarantine){
		func(x *TechnicalNodeQuarantine){x.StoreID=uuid.NewString()},
		func(x *TechnicalNodeQuarantine){x.OperationID=uuid.NewString()},
		func(x *TechnicalNodeQuarantine){x.Phase="RETIRING"},
		func(x *TechnicalNodeQuarantine){x.ConfirmedNode=uuid.NewString()},
		func(x *TechnicalNodeQuarantine){x.OperatorRef="other-operator"},
		func(x *TechnicalNodeQuarantine){x.EvidenceSHA256=hex.EncodeToString(make([]byte,32))},
	}{
		wrong:=q; mutate(&wrong)
		if err:=QuarantineTechnicalNode(ctx,db,wrong);err==nil {
			t.Fatalf("untrusted or conflicting quarantine re-opened incident: %+v",wrong)
		}
	}
	var original, operationState string
	var rateUp, rateDown, slots int64
	err=db.QueryRowContext(ctx,`SELECT p.state,o.state,
		g.committed_up,g.committed_down,e.active_slots
		FROM elx_technical_profiles p
		JOIN elx_technical_profile_operations o ON o.profile_id=p.profile_id
		JOIN elx_rate_grants g ON g.node_id=p.node_id AND g.resource_id=p.resource_id
		JOIN elx_entitlements e ON e.id=g.entitlement_id
		WHERE p.profile_id=$1 AND o.operation_id=$2`,
		profile,install).Scan(&original,&operationState,&rateUp,&rateDown,&slots)
	if err != nil {t.Fatal(err)}
	if original!="prepared"||operationState!="INTENT"||
		rateUp!=250000||rateDown!=250000||slots!=2 {
		t.Fatalf("quarantine fabricated APPLIED or released purchased rights: %s/%s %d/%d %d",original,operationState,rateUp,rateDown,slots)
	}
	// Even a future accidental administrative UPDATE/DELETE must fail.
	if _, err := db.ExecContext(ctx, `UPDATE elx_technical_node_quarantines
		SET operator_ref='overwritten' WHERE node_id=$1`, node); err == nil {
		t.Fatal("operator incident row was mutable")
	}
	if _, err := db.ExecContext(ctx, `DELETE FROM elx_technical_node_quarantines
		WHERE node_id=$1`, node); err == nil {
		t.Fatal("operator quarantine was removable")
	}
	// No success receipt is generated: Control still retains its INTENT.
}
