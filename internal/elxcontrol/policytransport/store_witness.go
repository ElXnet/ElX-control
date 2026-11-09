package policytransport

import (
 "context"
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
 if w.Version!=1{return nil}
 return fmt.Appendf(nil,"elx-control-store-witness-v1\n%s\n%s\n%s\n%s\n%d\n%d\n%s\n%s\n%s\n%d\n%d",
  w.NodeID,w.ResourceID,w.ExecutorID,w.StoreID,w.AuthorityGeneration,w.CoreRevision,
  w.CoreIncarnation,w.LastOperationID,w.Nonce,w.NotBefore,w.NotAfter)
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
 // A witness cannot advertise grants while an unresolved command exists:
 // first require authenticated APPLIED receipt and atomic DB commit.
 if _,err:=journal.Pending(ctx,s.db,binding.Target);err==nil{
  return nil,status.Error(codes.FailedPrecondition,"Control policy operation still unconfirmed")
 }else if !errors.Is(err,sql.ErrNoRows){
  return nil,status.Error(codes.Unavailable,"pending state unavailable")
 }
 nonce,err:=uuid.Parse(req.Nonce)
 if err!=nil || nonce==uuid.Nil{return nil,status.Error(codes.InvalidArgument,"invalid core nonce")}
 now:=time.Now().UTC().Unix()
 w:=SignedStoreWitness{Version:1,NodeID:state.NodeID,ResourceID:state.ResourceID,
  ExecutorID:state.ExecutorID,StoreID:state.StoreID,
  AuthorityGeneration:state.AuthorityGeneration,CoreRevision:state.CoreRevision,
  CoreIncarnation:state.CoreIncarnation,LastOperationID:state.LastOperationID,
  Nonce:req.Nonce,NotBefore:now,NotAfter:now+15}
 w.Signature=ed25519.Sign(s.leaseKey,WitnessTranscript(w))
 data,err:=json.Marshal(w);if err!=nil{return nil,status.Error(codes.Internal,"cannot encode signed store witness")}
 return wrapperspb.Bytes(data),nil
}
