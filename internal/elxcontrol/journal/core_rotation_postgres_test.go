package journal

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"testing"

	"github.com/ElXnet/ElX-control/internal/elxcontrol/session"
	"github.com/google/uuid"
)

func TestCoreRotationRequiresSignedDrainAndRetainsOccupiedSessions(t *testing.T){
	ctx,db:=testDatabase(t)
	ent,node,res,oldBoot,newBoot:=uuid.New(),uuid.New(),uuid.New(),uuid.New(),uuid.New()
	oldPub,oldPriv,err:=ed25519.GenerateKey(nil)
	checkError(t,err,nil)
	newPub,_,err:=ed25519.GenerateKey(nil)
	checkError(t,err,nil)
	_,err=db.ExecContext(ctx,`INSERT INTO elx_entitlements(id,active_slots,valid_until)
	 VALUES($1,2,clock_timestamp()+interval '1 day')`,ent)
	checkError(t,err,nil)
	_,err=db.ExecContext(ctx,`INSERT INTO elx_rate_budgets
	 (entitlement_id,up_limit,down_limit) VALUES($1,1000,1000)`,ent)
	checkError(t,err,nil)
	target:=Target{NodeID:node.String(),ResourceID:res.String()}
	_,err=db.ExecContext(ctx,`INSERT INTO elx_operation_targets(node_id,resource_id) VALUES($1,$2)`,node,res)
	checkError(t,err,nil)
	_,err=db.ExecContext(ctx,`INSERT INTO elx_rate_grants
	 (entitlement_id,node_id,resource_id,committed_up,committed_down,epoch,barrier_public_key)
	 VALUES($1,$2,$3,500,500,1,$4)`,ent,node,res,[]byte(oldPub))
	checkError(t,err,nil)
	_,err=db.ExecContext(ctx,`INSERT INTO elx_core_identities(node_id,incarnation,public_key)
	 VALUES($1,$2,$3)`,node,oldBoot,[]byte(oldPub))
	checkError(t,err,nil)
	// A live pressure high-watermark belongs to the retiring core and may
	// only be purged after cryptographic fencing and successful cutover.
	_,err=db.ExecContext(ctx,`INSERT INTO elx_rate_pressure_samples
	 (node_id,resource_id,incarnation,sequence,sampled_at,core_revision,
	  policy_up,policy_down,up_bytes,down_bytes,up_blocked_calls,down_blocked_calls,
	  up_blocked_nanos,down_blocked_nanos,up_waiters,down_waiters)
	 VALUES($1,$2,$3,1,clock_timestamp(),1,500,500,1,1,0,0,0,0,0,0)`,
	 node,res,oldBoot)
	checkError(t,err,nil)
	// The paid node inventory and rate epoch must rotate atomically too.
	_,err=db.ExecContext(ctx,`INSERT INTO elx_node_inventory(node_id,incarnation,enabled)
	 VALUES($1,$2,true)`,node,oldBoot)
	checkError(t,err,nil)
	paidProfile:=uuid.New()
	_,err=db.ExecContext(ctx,`INSERT INTO elx_paid_profiles
	 (id,entitlement_id,vless_id,subscription_id,client_email)
	 VALUES($1,$2,$3,$4,$5)`,paidProfile,ent,uuid.New(),
	 uuid.NewString(),"elx-rotation-"+paidProfile.String())
	checkError(t,err,nil)
	_,err=db.ExecContext(ctx,`INSERT INTO elx_paid_profile_nodes
	 (profile_id,node_id,resource_id,epoch) VALUES($1,$2,$3,1)`,
	 paidProfile,node,res)
	checkError(t,err,nil)

	device,profile,operation,owner:=uuid.New(),uuid.New(),uuid.New(),uuid.New()
	devicePub,_,err:=ed25519.GenerateKey(nil)
	checkError(t,err,nil)
	_,err=db.ExecContext(ctx,`INSERT INTO elx_devices
	 (id,entitlement_id,key_generation,public_key) VALUES($1,$2,1,$3)`,
	 device,ent,[]byte(devicePub))
	checkError(t,err,nil)
	_,err=db.ExecContext(ctx,`INSERT INTO elx_session_owners
	 (id,entitlement_id,device_id,node_id,operation_id,generation,key_generation,
	  proof_hash,state,core_incarnation,profile_id)
	 VALUES($1,$2,$3,$4,$5,1,1,$6,'active',$7,$8)`,
	 owner,ent,device,node,operation,make([]byte,32),oldBoot,profile)
	checkError(t,err,nil)

	rotationID:=uuid.NewString()
	rotation,err:=BeginCoreRotation(ctx,db,rotationID,node.String(),
	 oldBoot.String(),newBoot.String(),newPub)
	checkError(t,err,nil)
	if rotation.State!="quiescing"{t.Fatalf("rotation not quiescing: %+v",rotation)}
	replay,err:=BeginCoreRotation(ctx,db,rotationID,node.String(),
	 oldBoot.String(),newBoot.String(),newPub)
	checkError(t,err,nil)
	if !replay.AlreadyExisted{t.Fatal("rotation idempotency failed")}
	if _,err=BeginCoreRotation(ctx,db,uuid.NewString(),node.String(),
	 oldBoot.String(),uuid.NewString(),newPub);err==nil{
		t.Fatal("second rotation opened on already quiescing node")
	}

	intent:=session.Admission{EntitlementID:ent,DeviceID:device,NodeID:node,
	 OperationID:uuid.New(),KeyGeneration:1,Incarnation:oldBoot,
	 ProfileID:profile,HandshakeHash:[32]byte{1},FlowBinding:[32]byte{2}}
	if _,err=session.IssueChallenge(ctx,db,intent);!errors.Is(err,session.ErrDenied){
		t.Fatalf("old core admitted device during rotation: %v",err)
	}
	if _,err=QueueRateMove(ctx,db,ent.String(),target,uuid.NewString(),0,
	  Rate{Up:600,Down:600});!errors.Is(err,ErrPending){
		t.Fatalf("rotating core allowed positive rate move: %v",err)
	}
	if _,err=CompleteCoreRotation(ctx,db,rotationID);!errors.Is(err,ErrRotation){
		t.Fatalf("core rotated before grace/fence: %v",err)
	}
	// Time travel only inside this isolated test database.
	_,err=db.ExecContext(ctx,`UPDATE elx_core_rotations
	 SET earliest_cutover=clock_timestamp()-interval '1 second' WHERE id=$1`,rotationID)
	checkError(t,err,nil)
	if _,err=CompleteCoreRotation(ctx,db,rotationID);!errors.Is(err,ErrRotation){
		t.Fatalf("occupied active slot vanished without signed session fence: %v",err)
	}
	// Simulate a correctly confirmed signed session fence: session/fence
	// integration tests verify the cryptographic ReleaseAfterFence path.
	_,err=db.ExecContext(ctx,`UPDATE elx_session_owners SET state='released'
	 WHERE id=$1`,owner)
	checkError(t,err,nil)
	if _,err=CompleteCoreRotation(ctx,db,rotationID);!errors.Is(err,ErrRotation){
		t.Fatalf("live rate grant replaced without signed rate barrier: %v",err)
	}
	move:=uuid.NewString()
	_,err=QueueRateMove(ctx,db,ent.String(),target,move,0,Rate{})
	checkError(t,err,nil)
	cmd,err:=Pending(ctx,db,target)
	checkError(t,err,nil)
	hash:=sha256.Sum256(cmd.Payload)
	checkError(t,ConfirmApplied(ctx,db,target,move,1,hash),nil)
	checkError(t,FinalizeRateMove(ctx,db,ent.String(),target,move,nil),ErrRateBarrier)
	signed:=ed25519.Sign(oldPriv,rateBarrierMessage(ent.String(),target,move,1,1,Rate{}))
	checkError(t,FinalizeRateMove(ctx,db,ent.String(),target,move,signed),nil)
	rotation,err=CompleteCoreRotation(ctx,db,rotationID)
	checkError(t,err,nil)
	if rotation.State!="completed"{t.Fatalf("rotation incomplete: %+v",rotation)}
	again,err:=CompleteCoreRotation(ctx,db,rotationID)
	checkError(t,err,nil)
	if !again.AlreadyExisted{t.Fatal("completed rotation replay was not idempotent")}
	var oldRevoked,newRevoked bool
	var newEpoch int64
	var newKey []byte
	err=db.QueryRowContext(ctx,`SELECT revoked FROM elx_core_identities
	 WHERE node_id=$1 AND incarnation=$2`,node,oldBoot).Scan(&oldRevoked)
	checkError(t,err,nil)
	err=db.QueryRowContext(ctx,`SELECT revoked FROM elx_core_identities
	 WHERE node_id=$1 AND incarnation=$2`,node,newBoot).Scan(&newRevoked)
	checkError(t,err,nil)
	err=db.QueryRowContext(ctx,`SELECT epoch,barrier_public_key
	 FROM elx_rate_grants WHERE node_id=$1 AND resource_id=$2`,node,res).
	 Scan(&newEpoch,&newKey)
	checkError(t,err,nil)
	if !oldRevoked||newRevoked||newEpoch!=2||string(newKey)!=string(newPub){
		t.Fatalf("core pins not switched safely: old=%v new=%v epoch=%d",oldRevoked,newRevoked,newEpoch)
	}
	var inventoryBoot uuid.UUID
	var paidEpoch int64
	err=db.QueryRowContext(ctx,`SELECT incarnation FROM elx_node_inventory
	 WHERE node_id=$1`,node).Scan(&inventoryBoot)
	checkError(t,err,nil)
	err=db.QueryRowContext(ctx,`SELECT epoch FROM elx_paid_profile_nodes
	 WHERE profile_id=$1 AND node_id=$2`,paidProfile,node).Scan(&paidEpoch)
	checkError(t,err,nil)
	if inventoryBoot!=newBoot||paidEpoch!=2{
		t.Fatalf("paid node retained old core/epoch: boot=%s epoch=%d",inventoryBoot,paidEpoch)
	}
	var leftoverPressure int
	err=db.QueryRowContext(ctx,`SELECT count(*) FROM elx_rate_pressure_samples
	 WHERE node_id=$1 AND resource_id=$2`,node,res).Scan(&leftoverPressure)
	checkError(t,err,nil)
	if leftoverPressure!=0{
		t.Fatalf("retired core still owned %d pressure high watermarks",leftoverPressure)
	}
	if _,err=session.IssueChallenge(ctx,db,intent);!errors.Is(err,session.ErrDenied){
		t.Fatalf("retired incarnation admitted device after cutover: %v",err)
	}
}

func TestCoreRotationRejectsAmbiguousOrUnregisteredIdentity(t *testing.T){
	ctx,db:=testDatabase(t)
	node,oldBoot,newBoot:=uuid.New(),uuid.New(),uuid.New()
	pub,_,err:=ed25519.GenerateKey(nil)
	checkError(t,err,nil)
	if _,err=BeginCoreRotation(ctx,db,uuid.NewString(),node.String(),
	 oldBoot.String(),newBoot.String(),pub);!errors.Is(err,ErrRotationConflict){
		t.Fatalf("unregistered old core accepted: %v",err)
	}
	_,err=db.ExecContext(ctx,`INSERT INTO elx_core_identities(node_id,incarnation,public_key)
	 VALUES($1,$2,$3)`,node,oldBoot,[]byte(pub))
	checkError(t,err,nil)
	if _,err=BeginCoreRotation(ctx,db,uuid.NewString(),node.String(),
	 oldBoot.String(),newBoot.String(),pub);!errors.Is(err,ErrRotationConflict){
		t.Fatalf("same key on old and new core accepted: %v",err)
	}
}
