package journal

import (
 "context"
 "crypto/sha256"
 "database/sql"
 "errors"
 "fmt"

 "github.com/google/uuid"
)

// CoreStoreWitness is an independent PostgreSQL monotonic witness. A node
// cannot authorize a rollback by submitting its own snapshot or lease.
type CoreStoreWitness struct {
 NodeID string
 ResourceID string
 ExecutorID string
 StoreID string
 AuthorityGeneration uint64
 CoreRevision uint64
 CoreIncarnation string
 LastOperationID string
}

type CoreStoreReceipt struct {
 ExecutorID string
 StoreID string
 AuthorityGeneration uint64
 CoreRevision uint64
 CoreIncarnation string
 LastOperationID string
}

var ErrStoreWitness = errors.New("independent Control store witness mismatch")

func uuidValid(s string) bool {
 id, err := uuid.Parse(s)
 return err==nil && id!=uuid.Nil && id.String()==s
}

// ReadCoreStoreWitness reads the *Control* commit HWM, never node-local state.
func ReadCoreStoreWitness(ctx context.Context, db *sql.DB, target Target) (CoreStoreWitness,error) {
 if db==nil || !uuidValid(target.NodeID)||!uuidValid(target.ResourceID) {return CoreStoreWitness{},ErrStoreWitness}
 var w CoreStoreWitness
 var incarnation,operation sql.NullString
 var generation,revision int64
 err:=db.QueryRowContext(ctx,`SELECT node_id::text,resource_id::text,executor_id::text,store_id::text,
  authority_generation,core_revision,core_incarnation::text,last_operation_id::text
  FROM elx_core_store_witnesses WHERE node_id=$1 AND resource_id=$2`,
  target.NodeID,target.ResourceID).Scan(&w.NodeID,&w.ResourceID,&w.ExecutorID,&w.StoreID,
  &generation,&revision,&incarnation,&operation)
 if err!=nil {return CoreStoreWitness{},err}
 if generation<=0||revision<=0 {return CoreStoreWitness{},ErrStoreWitness}
 w.AuthorityGeneration=uint64(generation);w.CoreRevision=uint64(revision)
 if incarnation.Valid {w.CoreIncarnation=incarnation.String}
 if operation.Valid {w.LastOperationID=operation.String}
 return w,nil
}

// ProvisionCoreStoreWitness is an OFFLINE administrative primitive, not an
// RPC. A verified signed baseline from the running core and operator approval
// must precede calling it; this routine checks the DB revision/epoch and
// guards against accidental replacement, but is NOT a baseline attestor.
func ProvisionCoreStoreWitness(ctx context.Context, db *sql.DB, w CoreStoreWitness) error {
 if db==nil||!uuidValid(w.NodeID)||!uuidValid(w.ResourceID)||
  !uuidValid(w.ExecutorID)||!uuidValid(w.StoreID)||
  w.CoreIncarnation!=""||w.LastOperationID!=""||
  w.AuthorityGeneration==0||w.CoreRevision==0 {return ErrStoreWitness}
 tx,e:=db.BeginTx(ctx,nil);if e!=nil{return e};defer tx.Rollback()
 var revision,epoch int64
 e=tx.QueryRowContext(ctx,`SELECT t.revision,g.epoch FROM elx_operation_targets t
  JOIN elx_rate_grants g ON g.node_id=t.node_id AND g.resource_id=t.resource_id
  WHERE t.node_id=$1 AND t.resource_id=$2 FOR UPDATE OF t,g`,
  w.NodeID,w.ResourceID).Scan(&revision,&epoch)
 if e!=nil{return e}
 if revision<0||epoch<=0||uint64(revision)+1!=w.CoreRevision||
  uint64(epoch)!=w.AuthorityGeneration {return ErrStoreWitness}
 var pending bool
 e=tx.QueryRowContext(ctx,`SELECT EXISTS(
  SELECT 1 FROM elx_operations WHERE node_id=$1 AND resource_id=$2 AND applied_at IS NULL)`,
  w.NodeID,w.ResourceID).Scan(&pending)
 if e!=nil{return e};if pending{return ErrStoreWitness}
 _,e=tx.ExecContext(ctx,`INSERT INTO elx_core_store_witnesses(
  node_id,resource_id,executor_id,store_id,authority_generation,core_revision)
  VALUES ($1,$2,$3,$4,$5,$6) ON CONFLICT DO NOTHING`,
  w.NodeID,w.ResourceID,w.ExecutorID,w.StoreID,int64(w.AuthorityGeneration),int64(w.CoreRevision))
 if e!=nil{return e}
 var exists CoreStoreWitness
 var eg,er int64
 e=tx.QueryRowContext(ctx,`SELECT executor_id::text,store_id::text,
   authority_generation,core_revision FROM elx_core_store_witnesses
   WHERE node_id=$1 AND resource_id=$2 FOR UPDATE`,w.NodeID,w.ResourceID).
  Scan(&exists.ExecutorID,&exists.StoreID,&eg,&er)
 if e!=nil{return e}
 if exists.ExecutorID!=w.ExecutorID||exists.StoreID!=w.StoreID||
  eg!=int64(w.AuthorityGeneration)||er!=int64(w.CoreRevision) {return ErrStoreWitness}
 return tx.Commit()
}

// ConfirmAppliedWithStoreWitness atomically commits one signed APPLIED receipt,
// the operation-target revision, and the independent store HWM. Never confirm
// an operation and then update the witness in a separate transaction.
func ConfirmAppliedWithStoreWitness(ctx context.Context,db *sql.DB,target Target,
 id string,revision int64,hash [32]byte,receipt CoreStoreReceipt)error{
 if db==nil||!uuidValid(target.NodeID)||!uuidValid(target.ResourceID)||
  !uuidValid(id)||!uuidValid(receipt.ExecutorID)||!uuidValid(receipt.StoreID)||
  !uuidValid(receipt.CoreIncarnation)||receipt.LastOperationID!=id||
  receipt.AuthorityGeneration==0||receipt.CoreRevision==0||
  revision<=0||uint64(revision)+1!=receipt.CoreRevision||
  hash==[sha256.Size]byte{} {return ErrStoreWitness}
 tx,e:=db.BeginTx(ctx,nil);if e!=nil{return e};defer tx.Rollback()
 var current int64
 e=tx.QueryRowContext(ctx,`SELECT revision FROM elx_operation_targets
 WHERE node_id=$1 AND resource_id=$2 FOR UPDATE`,target.NodeID,target.ResourceID).Scan(&current)
 if e!=nil{return e}
 var applied bool
 e=tx.QueryRowContext(ctx,`SELECT applied_at IS NOT NULL FROM elx_operations
 WHERE node_id=$1 AND resource_id=$2 AND operation_id=$3 AND revision=$4 AND payload_hash=$5`,
 target.NodeID,target.ResourceID,id,revision,hash[:]).Scan(&applied)
 if errors.Is(e,sql.ErrNoRows){return ErrReceipt};if e!=nil{return e}
 var executor,storeID string
 var epoch,coreRevision int64
 e=tx.QueryRowContext(ctx,`SELECT executor_id::text,store_id::text,authority_generation,core_revision
 FROM elx_core_store_witnesses WHERE node_id=$1 AND resource_id=$2 FOR UPDATE`,
 target.NodeID,target.ResourceID).Scan(&executor,&storeID,&epoch,&coreRevision)
 if errors.Is(e,sql.ErrNoRows){return ErrStoreWitness};if e!=nil{return e}
 if executor!=receipt.ExecutorID||storeID!=receipt.StoreID||
  epoch<=0||uint64(epoch)!=receipt.AuthorityGeneration {return ErrStoreWitness}
 if applied {
  // An old receipt may be resent, but it can never lower a witness.
  if current<revision||coreRevision<int64(receipt.CoreRevision) {return ErrStoreWitness}
  return tx.Commit()
 }
 if current!=revision-1||coreRevision!=revision {return ErrRevision}
 result,e:=tx.ExecContext(ctx,`UPDATE elx_operations SET applied_at=clock_timestamp()
 WHERE node_id=$1 AND resource_id=$2 AND operation_id=$3 AND applied_at IS NULL`,
 target.NodeID,target.ResourceID,id)
 if e!=nil{return e};n,e:=result.RowsAffected();if e!=nil||n!=1{return ErrStoreWitness}
 result,e=tx.ExecContext(ctx,`UPDATE elx_operation_targets SET revision=$3
 WHERE node_id=$1 AND resource_id=$2 AND revision=$4`,
 target.NodeID,target.ResourceID,revision,revision-1)
 if e!=nil{return e};n,e=result.RowsAffected();if e!=nil||n!=1{return ErrRevision}
 result,e=tx.ExecContext(ctx,`UPDATE elx_core_store_witnesses SET
 core_revision=$3,core_incarnation=$4,last_operation_id=$5,updated_at=clock_timestamp()
 WHERE node_id=$1 AND resource_id=$2 AND core_revision=$6`,
 target.NodeID,target.ResourceID,int64(receipt.CoreRevision),receipt.CoreIncarnation,id,revision)
 if e!=nil{return e};n,e=result.RowsAffected();if e!=nil||n!=1{return ErrStoreWitness}
 return tx.Commit()
}

func (w CoreStoreWitness) String() string {
 return fmt.Sprintf("store=%s resource=%s coreRev=%d generation=%d",w.StoreID,w.ResourceID,w.CoreRevision,w.AuthorityGeneration)
}
