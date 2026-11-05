package corepolicy

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/session"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type fakeFenceCore interface {
	drain(context.Context,*wrapperspb.BytesValue)(*wrapperspb.BytesValue,error)
}
type fenceSigner struct { key ed25519.PrivateKey }
func (s *fenceSigner) drain(_ context.Context,r *wrapperspb.BytesValue)(*wrapperspb.BytesValue,error) {
	var f session.Fence
	if err:=json.Unmarshal(r.GetValue(),&f);err!=nil {return nil,err}
	return wrapperspb.Bytes(ed25519.Sign(s.key,session.FenceTranscript(f))),nil
}
func registerFakeFence(g *grpc.Server,signer *fenceSigner){
	g.RegisterService(&grpc.ServiceDesc{
		ServiceName:"xray.app.policy.command.ProfileFence",
		HandlerType:(*fakeFenceCore)(nil),
		Methods:[]grpc.MethodDesc{{MethodName:"Drain",Handler:func(s any,ctx context.Context,
			decode func(any)error,intercept grpc.UnaryServerInterceptor)(any,error){
			input:=new(wrapperspb.BytesValue)
			if err:=decode(input);err!=nil {return nil,err}
			if intercept==nil {return s.(*fenceSigner).drain(ctx,input)}
			return intercept(ctx,input,&grpc.UnaryServerInfo{
				Server:s,FullMethod:"/xray.app.policy.command.ProfileFence/Drain",
			},func(ctx context.Context,r any)(any,error){
				return s.(*fenceSigner).drain(ctx,r.(*wrapperspb.BytesValue))
			})
		}}},
	},signer)
}
func TestLocalProfileFenceProofUsesPinnedCoreKey(t *testing.T){
	pub,private,err:=ed25519.GenerateKey(nil)
	if err!=nil {t.Fatal(err)}
	_,other,err:=ed25519.GenerateKey(nil)
	if err!=nil {t.Fatal(err)}
	listener,err:=net.Listen("tcp","127.0.0.1:0")
	if err!=nil {t.Fatal(err)}
	g:=grpc.NewServer()
	registerFakeFence(g,&fenceSigner{key:private})
	go g.Serve(listener)
	t.Cleanup(func(){g.Stop();listener.Close()})
	conn,err:=grpc.NewClient(listener.Addr().String(),grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err!=nil {t.Fatal(err)}
	defer conn.Close()
	c:=&Client{conn:conn}
	f:=session.Fence{OwnerID:uuid.New(),ProfileID:uuid.New(),NodeID:uuid.New(),
		Incarnation:uuid.New(),Generation:3}
	ctx,cancel:=context.WithTimeout(context.Background(),time.Second*3)
	defer cancel()
	sig,err:=c.DrainProfile(ctx,f,pub)
	if err!=nil || !ed25519.Verify(pub,session.FenceTranscript(f),sig) {
		t.Fatalf("pinned core drain signature rejected: %v",err)
	}
	if _,err:=c.DrainProfile(ctx,f,other.Public().(ed25519.PublicKey));err==nil {
		t.Fatal("node accepted signature from an unpinned core")
	}
	empty:=f
	empty.ProfileID=uuid.Nil
	if _,err:=c.DrainProfile(ctx,empty,pub);err==nil {
		t.Fatal("missing VLESS profile accepted")
	}
}
