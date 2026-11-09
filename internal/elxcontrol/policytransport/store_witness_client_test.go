package policytransport

import (
 "context"
 "encoding/json"
 "errors"
 "testing"

 "github.com/google/uuid"
 "github.com/ElXnet/ElX-control/internal/elxcontrol/journal"
 "google.golang.org/grpc"
 "google.golang.org/protobuf/types/known/wrapperspb"
)

type witnessFakeConn struct {
 lease []byte
 witness []byte
 witnessRequests int
 sawNonce string
}
func (f *witnessFakeConn) Invoke(_ context.Context, method string, request, reply any, _ ...grpc.CallOption) error {
 switch method {
 case "/"+serviceName+"/Lease":
  reply.(*wrapperspb.BytesValue).Value=append([]byte(nil),f.lease...)
  return nil
 case "/"+serviceName+"/StoreWitness":
  f.witnessRequests++
  var r WitnessRequest
  if err:=json.Unmarshal(request.(*wrapperspb.BytesValue).Value,&r);err!=nil{return err}
  f.sawNonce=r.Nonce
  reply.(*wrapperspb.BytesValue).Value=append([]byte(nil),f.witness...)
  return nil
 default:
  return errors.New("unexpected store witness RPC")
 }
}
func (*witnessFakeConn) NewStream(context.Context, *grpc.StreamDesc, string, ...grpc.CallOption)(grpc.ClientStream,error){
 return nil,errors.New("stream unsupported")
}
type witnessFakeCore struct {
 nonce string
 classic int
 managed int
 signedLease []byte
 signedWitness []byte
}
func (c *witnessFakeCore) RenewControlLease(_ context.Context, ticket []byte) error {
 c.classic++
 return nil
}
func (c *witnessFakeCore) ManagedWitnessNonce(context.Context,string)(string,error){
 return c.nonce,nil
}
func (c *witnessFakeCore) RenewControlLeaseWithWitness(_ context.Context,ticket,witness []byte)error{
 c.managed++
 c.signedLease=append([]byte(nil),ticket...)
 c.signedWitness=append([]byte(nil),witness...)
 return nil
}
type legacyWitnessCore struct{ classic int }
func (c *legacyWitnessCore) RenewControlLease(context.Context,[]byte)error{c.classic++;return nil}

func TestSignedStoreWitnessRequiredBeforeRenewLease(t *testing.T){
 t.Setenv("ELX_AGENT_STORE_WITNESS_REQUIRED","1")
 nonce:=uuid.NewString()
 b:=Binding{Target:journal.Target{NodeID:uuid.NewString(),ResourceID:uuid.NewString()},
  Subscription:"lab",ExecutorID:uuid.NewString(),Epoch:9,
  PublicKey:make([]byte,32)}
 f:=&witnessFakeConn{lease:[]byte("lease"),witness:[]byte("signed-store-witness")}
 core:=&witnessFakeCore{nonce:nonce}
 if e:=ApplyLease(context.Background(),f,core,b);e!=nil{t.Fatal(e)}
 if core.managed!=1||core.classic!=0||f.witnessRequests!=1||
  string(core.signedLease)!="lease"||string(core.signedWitness)!="signed-store-witness"||
  f.sawNonce!=nonce {t.Fatal("stage3 signed HWM was not required for lease")}
 legacy:=new(legacyWitnessCore)
 if e:=ApplyLease(context.Background(),f,legacy,b);e==nil||legacy.classic!=0{
  t.Fatal("stage3 lease silently downgraded to old core")
 }
 f.witness=nil
 if e:=ApplyLease(context.Background(),f,core,b);e==nil||core.managed!=1{
  t.Fatal("missing Control HWM renewed paid lease")
 }
}

func TestLegacyLeasePathUnchangedWithoutStage3Flag(t *testing.T){
 t.Setenv("ELX_AGENT_STORE_WITNESS_REQUIRED","")
 b:=Binding{Target:journal.Target{NodeID:uuid.NewString(),ResourceID:uuid.NewString()},
  Subscription:"lab",PublicKey:make([]byte,32),Epoch:1}
 f:=&witnessFakeConn{lease:[]byte("lease")}
 core:=new(legacyWitnessCore)
 if e:=ApplyLease(context.Background(),f,core,b);e!=nil||core.classic!=1||f.witnessRequests!=0{
  t.Fatalf("legacy stage-2 lease interoperability lost: %v",e)
 }
}
