package policytransport

import (
 "context"
 "crypto/sha256"
 "encoding/hex"
 "sort"
 "crypto/ed25519"
 "database/sql"
 "encoding/json"
 "errors"
 "fmt"
 "time"

 "github.com/ElXnet/ElX-control/internal/elxcontrol/journal"
 "github.com/google/uuid"
 "google.golang.org/grpc/codes"
 "google.golang.org/grpc/status"
 "google.golang.org/protobuf/types/known/wrapperspb"
)

// A short-lived, core-boot-nonce-bound, signed Control PostgreSQL HWM. An
// attacker who restores image+anchor cannot reuse a previous boot's witness.
type SignedStoreWitness struct {
 Version uint32
 NodeID string
 ResourceID string
 ExecutorID string
 StoreID string
 AuthorityGeneration uint64
 CoreRevision uint64
 CoreIncarnation string
 LastOperationID string
 TombstonesSHA256 string
 Nonce string
 NotBefore int64
 NotAfter int64
 Signature []byte
}
type WitnessRequest struct {
 ResourceID string
 Subscription string
 Nonce string
}

func WitnessTranscript(w SignedStoreWitness) []byte {
 if w.Version!=2{return nil}
 return fmt.Appendf(nil,"elx-control-store-witness-v2\n%s\n%s\n%s\n%s\n%d\n%d\n%s\n%s\n%s\n%s\n%d\n%d",
  w.NodeID,w.ResourceID,w.ExecutorID,w.StoreID,w.AuthorityGeneration,w.CoreRevision,
  w.CoreIncarnation,w.LastOperationID,w.TombstonesSHA256,w.Nonce,w.NotBefore,w.NotAfter)
}

// Control's authoritative denial high-water covers every profile that
// has reached draining or released state. A coordinated old disk restore
// cannot omit this set: it must match the exact local journal tombstones.
// A pending drain without a local tombstone blocks paid admission (safe).
func controlTombstoneDigest(ctx context.Context,db *sql.DB,nodeID string)(string,error) {
 rows,err:=db.QueryContext(ctx,`SELECT profile_id::text,MAX(generation)
  FROM elx_session_owners
  WHERE node_id=$1 AND profile_id IS NOT NULL
  AND state IN ('draining','released')
  GROUP BY profile_id ORDER BY profile_id`,nodeID)
 if err!=nil{return "",err}
 defer rows.Close()
 entries:=make([]string,0)
 for rows.Next(){
  var profile string
  var generation int64
  if err:=rows.Scan(&profile,&generation);err!=nil{return "",err}
  if !validID(profile)||generation<=0{return "",errors.New("invalid Control denial baseline")}
  entries=append(entries,fmt.Sprintf("%s\n%d\n",profile,generation))
 }
 if err:=rows.Err();err!=nil{return "",err}
 return tombstoneDigestFromEntries(entries),nil
}

// Shared by the SQL-backed signer and offline golden negative fixtures.
// Entries are canonical UUID + newline + signed int64 generation + newline.
func tombstoneDigestFromEntries(entries []string) string {
 sort.Strings(entries)
 h:=sha256.New()
 _,_ = h.Write([]byte("elx-denied-profile-v1\n"))
 for _,entry:=range entries{_,_ = h.Write([]byte(entry))}
 return hex.EncodeToString(h.Sum(nil))
}

func (s *server) witness(ctx context.Context,in *wrapperspb.BytesValue)(*wrapperspb.BytesValue,error) {
 bindings,err:=s.authorize(ctx);if err!=nil{return nil,err}
 if len(s.leaseKey)!=ed25519.PrivateKeySize{return nil,status.Error(codes.FailedPrecondition,"Control witness signer unavailable")}
 if len(in.GetValue())==0||len(in.GetValue())>512{return nil,status.Error(codes.InvalidArgument,"invalid witness request")}
 var req WitnessRequest
 if json.Unmarshal(in.GetValue(),&req)!=nil||!validID(req.ResourceID)||
  req.Subscription==""||len(req.Subscription)>1024||!validID(req.Nonce){
  return nil,status.Error(codes.InvalidArgument,"invalid signed witness binding")
 }
 var binding *Binding
 for i:=range bindings{
  if bindings[i].Target.ResourceID==req.ResourceID && bindings[i].Subscription==req.Subscription{
   binding=&bindings[i];break
  }
 }
 if binding==nil || !validID(binding.ExecutorID){return nil,status.Error(codes.PermissionDenied,"witness node/executor not assigned")}
 state,err:=journal.ReadCoreStoreWitness(ctx,s.db,binding.Target)
 if errors.Is(err,sql.ErrNoRows){return nil,status.Error(codes.FailedPrecondition,"independent Control HWM not provisioned")}
 if err!=nil{return nil,status.Error(codes.Unavailable,"Control HWM database unavailable")}
 if state.NodeID!=binding.Target.NodeID||state.ResourceID!=binding.Target.ResourceID||
  state.ExecutorID!=binding.ExecutorID||state.AuthorityGeneration!=uint64(binding.Epoch)||
  !validID(state.StoreID){
  return nil,status.Error(codes.FailedPrecondition,"Control witness epoch/store binding superseded")
 }
 // The independent store witness attests the PREVIOUS committed core
 // snapshot, never the pending rate move itself. Allow precisely one
 // pending, durably budget-reserved next-revision rate move. Otherwise a
 // scheduler raise deadlocks: the new signed ceiling is reserved, but the
 // core cannot accept it without a fresh witness matching the still-old
 // live revision. If that rate was already applied without an ACK, the core
 // sees the old witness revision and independently rejects it (fail closed).
 // Any unrelated pending mutation remains blocked.
 if pending,pendingErr:=journal.Pending(ctx,s.db,binding.Target);pendingErr==nil {
  var reservedNextRate bool
  err=s.db.QueryRowContext(ctx,`SELECT EXISTS (
    SELECT 1 FROM elx_rate_moves m
    JOIN elx_operations o ON o.node_id=m.node_id
      AND o.resource_id=m.resource_id AND o.operation_id=m.operation_id
    JOIN elx_core_store_witnesses w ON w.node_id=o.node_id
      AND w.resource_id=o.resource_id
    JOIN elx_rate_grants g ON g.node_id=o.node_id
      AND g.resource_id=o.resource_id
    WHERE o.node_id=$1 AND o.resource_id=$2 AND o.operation_id=$3
      AND m.finalized=false AND o.applied_at IS NULL
      AND o.revision-1=w.core_revision
      AND w.authority_generation=g.epoch AND g.epoch=$4
      AND g.entitlement_id IS NOT NULL
  )`,binding.Target.NodeID,binding.Target.ResourceID,pending.ID,binding.Epoch).
   Scan(&reservedNextRate)
  if err!=nil {
   return nil,status.Error(codes.Unavailable,"pending rate witness eligibility unavailable")
  }
  if !reservedNextRate {
   return nil,status.Error(codes.FailedPrecondition,"unconfirmed non-rate operation or divergent witness")
  }
 }else if !errors.Is(pendingErr,sql.ErrNoRows){
  return nil,status.Error(codes.Unavailable,"pending state unavailable")
 }
 nonce,err:=uuid.Parse(req.Nonce)
 if err!=nil || nonce==uuid.Nil{return nil,status.Error(codes.InvalidArgument,"invalid core nonce")}
 now:=time.Now().UTC().Unix()
 tombstoneDigest,err:=controlTombstoneDigest(ctx,s.db,state.NodeID)
 if err!=nil{return nil,status.Error(codes.Unavailable,"Control session-denial HWM unavailable")}
 w:=SignedStoreWitness{Version:2,NodeID:state.NodeID,ResourceID:state.ResourceID,
  ExecutorID:state.ExecutorID,StoreID:state.StoreID,
  AuthorityGeneration:state.AuthorityGeneration,CoreRevision:state.CoreRevision,
  CoreIncarnation:state.CoreIncarnation,LastOperationID:state.LastOperationID,
  TombstonesSHA256:tombstoneDigest,
  Nonce:req.Nonce,NotBefore:now,NotAfter:now+15}
 w.Signature=ed25519.Sign(s.leaseKey,WitnessTranscript(w))
 data,err:=json.Marshal(w);if err!=nil{return nil,status.Error(codes.Internal,"cannot encode signed store witness")}
 return wrapperspb.Bytes(data),nil
}
