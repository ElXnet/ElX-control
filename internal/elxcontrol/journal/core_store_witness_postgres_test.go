package journal

import (
 "crypto/ed25519"
 "crypto/sha256"
 "database/sql"
 "errors"
 "testing"

 "github.com/google/uuid"
)

func TestPostgresIndependentStoreWitnessRejectsDoubleSnapshotRollback(t *testing.T){
 ctx,db:=testDatabase(t)
 ent:=uuid.NewString()
 target:=Target{NodeID:uuid.NewString(),ResourceID:uuid.NewString()}
 executor,store:=uuid.NewString(),uuid.NewString()
 _,e:=db.ExecContext(ctx,`INSERT INTO elx_entitlements(id,active_slots,valid_until)
  VALUES($1,1,clock_timestamp()+interval '1 hour')`,ent)
 checkError(t,e,nil)
 _,e=db.ExecContext(ctx,`INSERT INTO elx_rate_budgets(entitlement_id,up_limit,down_limit)
  VALUES($1,100,100)`,ent)
 checkError(t,e,nil)
 _,e=db.ExecContext(ctx,`INSERT INTO elx_operation_targets(node_id,resource_id)
  VALUES($1,$2)`,target.NodeID,target.ResourceID)
 checkError(t,e,nil)
 pub,_,e:=ed25519.GenerateKey(nil);checkError(t,e,nil)
 _,e=db.ExecContext(ctx,`INSERT INTO elx_rate_grants
  (entitlement_id,node_id,resource_id,committed_up,committed_down,epoch,barrier_public_key)
  VALUES($1,$2,$3,100,100,9,$4)`,ent,target.NodeID,target.ResourceID,[]byte(pub))
 checkError(t,e,nil)
 baseline:=CoreStoreWitness{NodeID:target.NodeID,ResourceID:target.ResourceID,
  ExecutorID:executor,StoreID:store,AuthorityGeneration:9,CoreRevision:1}
 checkError(t,ProvisionCoreStoreWitness(ctx,db,baseline),nil)
 checkError(t,ProvisionCoreStoreWitness(ctx,db,baseline),nil)
 wrong:=baseline;wrong.StoreID=uuid.NewString()
 checkError(t,ProvisionCoreStoreWitness(ctx,db,wrong),ErrStoreWitness)
 wrong=baseline;wrong.CoreRevision=2
 checkError(t,ProvisionCoreStoreWitness(ctx,db,wrong),ErrStoreWitness)

 id:=uuid.NewString()
 payload:=[]byte(`{"Up":90,"Down":90,"Disabled":false}`)
 hash:=sha256.Sum256(payload)
 _,e=db.ExecContext(ctx,`INSERT INTO elx_operations
 (node_id,resource_id,operation_id,revision,payload,payload_hash)
 VALUES($1,$2,$3,1,$4,$5)`,target.NodeID,target.ResourceID,id,payload,hash[:])
 checkError(t,e,nil)
 receipt:=CoreStoreReceipt{ExecutorID:executor,StoreID:store,AuthorityGeneration:9,
  CoreRevision:2,CoreIncarnation:uuid.NewString(),LastOperationID:id}
 tampered:=receipt;tampered.StoreID=uuid.NewString()
 checkError(t,ConfirmAppliedWithStoreWitness(ctx,db,target,id,1,hash,tampered),ErrStoreWitness)
 tampered=receipt;tampered.AuthorityGeneration=8
 checkError(t,ConfirmAppliedWithStoreWitness(ctx,db,target,id,1,hash,tampered),ErrStoreWitness)
 _,e=Pending(ctx,db,target);if e!=nil{t.Fatal("bad signature must not acknowledge pending operation:",e)}

 checkError(t,ConfirmAppliedWithStoreWitness(ctx,db,target,id,1,hash,receipt),nil)
 checkError(t,ConfirmAppliedWithStoreWitness(ctx,db,target,id,1,hash,receipt),nil)
 stored,e:=ReadCoreStoreWitness(ctx,db,target);checkError(t,e,nil)
 if stored.StoreID!=store||stored.ExecutorID!=executor||stored.CoreRevision!=2||
  stored.AuthorityGeneration!=9||stored.CoreIncarnation!=receipt.CoreIncarnation||
  stored.LastOperationID!=id{
  t.Fatalf("independent HWM not updated atomically with command ACK: %+v",stored)
 }
 // A coordinated rollback of the local image+anchor to revision 1 must
 // disagree with the authoritative PostgreSQL revision 2.
 if stored.CoreRevision==baseline.CoreRevision{t.Fatal("Postgres HWM silently rolled back with node files")}
 if _,e=Pending(ctx,db,target);!errors.Is(e,sql.ErrNoRows){t.Fatalf("ACK did not complete: %v",e)}
}
