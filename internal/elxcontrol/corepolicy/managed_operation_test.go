package corepolicy

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"strconv"
	"sync"
	"testing"

	"github.com/google/uuid"
	wire "github.com/ElXnet/ElX-control/internal/elxcontrol/corepolicy/wire"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
)

type managedPolicyProbe struct {
	wire.UnimplementedSubscriptionServiceServer
	mu sync.Mutex
	key ed25519.PrivateKey
	policy Policy
	mutations int
	incoming metadata.MD
}
func (s *managedPolicyProbe) GetSubscription(ctx context.Context, r *wire.GetSubscriptionRequest) (*wire.Subscription,error) {
	s.mu.Lock()
	p:=s.policy
	appliedMD:=s.incoming.Copy()
	s.mu.Unlock()
	md,_:=metadata.FromIncomingContext(ctx)
	if challenge:=md.Get("elx-policy-challenge");len(challenge)==1 {
		proof:=ed25519.Sign(s.key,fmt.Appendf(nil,"elx-policy-v1\n%x\n%x\n%d\n%d\n%d\n%t",
			challenge[0],p.ID,p.Revision,p.UplinkBps,p.DownlinkBps,p.Disabled))
		if err:=grpc.SetHeader(ctx,metadata.Pairs("elx-policy-proof",hex.EncodeToString(proof)));err!=nil{return nil,err}
	}
	if requested:=md.Get("elx-op-readback-id");len(requested)==1 {
		challenge:=md.Get("elx-op-readback-challenge")
		if len(challenge)!=1 {return nil,fmt.Errorf("missing operation challenge")}
		value:=func(field string) string {v:=appliedMD.Get(field);if len(v)!=1{return ""};return v[0]}
		epoch,_:=strconv.ParseUint(value("elx-op-generation"),10,64)
		receipt:=AppliedEvidence{
			Version:1,OperationID:requested[0],PayloadSHA256:value("elx-op-hash"),
			NodeID:value("elx-op-node"),ExecutorID:value("elx-op-executor"),
			ResourceID:value("elx-op-resource"),AuthorityGeneration:epoch,
			Revision:p.Revision,CoreIncarnation:"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
			StoreID:"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",CompletedUnixNanos:1700000000000000000,
		}
		message:=fmt.Appendf(nil,"elx-applied-operation-v1\n%x\n%s\n%s\n%s\n%s\n%s\n%d\n%d\n%s\n%s\n%d",
			challenge[0],receipt.OperationID,receipt.PayloadSHA256,receipt.NodeID,receipt.ExecutorID,
			receipt.ResourceID,receipt.AuthorityGeneration,receipt.Revision,receipt.CoreIncarnation,
			receipt.StoreID,receipt.CompletedUnixNanos)
		receipt.Signature=ed25519.Sign(s.key,message)
		encoded,_:=json.Marshal(receipt)
		if err:=grpc.SetHeader(ctx,metadata.Pairs("elx-operation-receipt-bin",string(encoded)));err!=nil{return nil,err}
	}
	return &wire.Subscription{Id:p.ID,Revision:p.Revision,UplinkBps:p.UplinkBps,DownlinkBps:p.DownlinkBps,Disabled:p.Disabled},nil
}
func (s *managedPolicyProbe) SetSubscription(ctx context.Context,r *wire.SetSubscriptionRequest)(*wire.Subscription,error){
	md,_:=metadata.FromIncomingContext(ctx)
	s.mu.Lock()
	defer s.mu.Unlock()
	s.mutations++
	s.incoming=md.Copy()
	s.policy=Policy{ID:r.Id,Revision:r.Revision,UplinkBps:r.GetUplinkBps(),DownlinkBps:r.GetDownlinkBps(),Disabled:r.GetDisabled()}
	return &wire.Subscription{Id:r.Id,Revision:r.Revision},nil
}
func TestManagedControlAdapterBindsExactMutationToOperation(t *testing.T) {
	key:=ed25519.NewKeyFromSeed(make([]byte,ed25519.SeedSize))
	server:=&managedPolicyProbe{key:key,policy:Policy{ID:"lab",Revision:1,UplinkBps:100,DownlinkBps:200}}
	listen,err:=net.Listen("tcp","127.0.0.1:0")
	if err!=nil{t.Fatal(err)}
	grpcServer:=grpc.NewServer()
	wire.RegisterSubscriptionServiceServer(grpcServer,server)
	go grpcServer.Serve(listen)
	t.Cleanup(grpcServer.Stop)
	conn,err:=grpc.NewClient(listen.Addr().String(),grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err!=nil{t.Fatal(err)}
	defer conn.Close()
	client:=&Client{conn:conn,rpc:wire.NewSubscriptionServiceClient(conn)}
	node,resource,executor,op:=uuid.NewString(),uuid.NewString(),uuid.NewString(),uuid.NewString()
	result,err:=client.ApplyManagedWithProof(context.Background(),Policy{ID:"lab",Revision:2,UplinkBps:90,DownlinkBps:180},"challenge",
		key.Public().(ed25519.PublicKey),ManagedOperation{
		OperationID:op,NodeID:node,ExecutorID:executor,ResourceID:resource,AuthorityGeneration:9,
	})
	if err!=nil{t.Fatal(err)}
	if len(result)<=ed25519.SignatureSize || !VerifyAppliedEvidence(key.Public().(ed25519.PublicKey),"challenge",
		ManagedOperation{OperationID:op,NodeID:node,ExecutorID:executor,ResourceID:resource,AuthorityGeneration:9},
		Policy{ID:"lab",Revision:2,UplinkBps:90,DownlinkBps:180},result[ed25519.SignatureSize:]) {
		t.Fatal("core applied-operation evidence missing or invalid")
	}
	server.mu.Lock()
	defer server.mu.Unlock()
	if server.mutations!=1 {t.Fatalf("unexpected writes: %d",server.mutations)}
	for key,want:=range map[string]string{
		"elx-op-id":op,"elx-op-node":node,"elx-op-resource":resource,
		"elx-op-executor":executor,"elx-op-generation":"9",
		"elx-op-hash":"4255081ce063d5fc3a34d2099448e626e4202b80197d47d26b200ec2d19193bd",
	} {
		found:=server.incoming.Get(key)
		if len(found)!=1||found[0]!=want {t.Fatalf("%s: %q, expected %q",key,found,want)}
	}
}
