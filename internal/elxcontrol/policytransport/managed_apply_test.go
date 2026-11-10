package policytransport

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/google/uuid"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/corepolicy"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type managedFakeConn struct {
	job []byte
	confirmed bool
	received receipt
}
func (f *managedFakeConn) Invoke(_ context.Context, method string, request any, reply any, _ ...grpc.CallOption) error {
	if strings.HasSuffix(method, "/Next") {
		reply.(*wrapperspb.BytesValue).Value=f.job
		return nil
	}
	if strings.HasSuffix(method, "/Confirm") {
		f.confirmed=true
		return json.Unmarshal(request.(*wrapperspb.BytesValue).Value, &f.received)
	}
	return errors.New("unexpected method")
}
func (*managedFakeConn) NewStream(context.Context, *grpc.StreamDesc, string, ...grpc.CallOption) (grpc.ClientStream,error) {
	return nil,errors.New("no streams in fixture")
}
type managedFakeCore struct {
	key ed25519.PrivateKey
	complete bool
}
func (m managedFakeCore) ApplyWithProof(context.Context, corepolicy.Policy, string, ed25519.PublicKey) ([]byte,error) {
	return nil,errors.New("managed v3 must not downgrade to legacy applier")
}
func (m managedFakeCore) ApplyManagedWithProof(_ context.Context, p corepolicy.Policy, challenge string, _ ed25519.PublicKey, op corepolicy.ManagedOperation) ([]byte,error) {
	policyProof:=ed25519.Sign(m.key,fmt.Appendf(nil,"elx-policy-v1\n%x\n%x\n%d\n%d\n%d\n%t",
		challenge,p.ID,p.Revision,p.UplinkBps,p.DownlinkBps,p.Disabled))
	if !m.complete {return policyProof,nil}
	r:=corepolicy.AppliedEvidence{
		Version:1,OperationID:op.OperationID,NodeID:op.NodeID,ResourceID:op.ResourceID,
		ExecutorID:op.ExecutorID,AuthorityGeneration:op.AuthorityGeneration,
		PayloadSHA256:corepolicy.ManagedMutationDigest(p),Revision:p.Revision,
		CoreIncarnation:"aaaaaaaa-aaaa-4aaa-8aaa-aaaaaaaaaaaa",
		StoreID:"bbbbbbbb-bbbb-4bbb-8bbb-bbbbbbbbbbbb",CompletedUnixNanos:1700000000000000000,
	}
	r.Signature=ed25519.Sign(m.key,fmt.Appendf(nil,"elx-applied-operation-v1\n%x\n%s\n%s\n%s\n%s\n%s\n%d\n%d\n%s\n%s\n%d",
		challenge,r.OperationID,r.PayloadSHA256,r.NodeID,r.ExecutorID,r.ResourceID,
		r.AuthorityGeneration,r.Revision,r.CoreIncarnation,r.StoreID,r.CompletedUnixNanos))
	encoded,err:=json.Marshal(r)
	if err!=nil{return nil,err}
	return append(policyProof,encoded...),nil
}
func TestManagedJobRequiresSeparateSignedAppliedReceipt(t *testing.T) {
	key:=ed25519.NewKeyFromSeed(make([]byte,ed25519.SeedSize))
	job:=Job{
		PublicKey:key.Public().(ed25519.PublicKey),
		Operation:uuid.NewString(),NodeID:uuid.NewString(),ResourceID:uuid.NewString(),
		ExecutorID:uuid.NewString(),AuthorityGeneration:9,
		Policy:corepolicy.Policy{ID:"lab",Revision:2,UplinkBps:90,DownlinkBps:180},
		Challenge:"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
	}
	data,err:=json.Marshal(job)
	if err!=nil{t.Fatal(err)}
	for _,completed:=range []bool{false,true} {
		f:=&managedFakeConn{job:data}
		err:=ApplyNext(context.Background(),f,managedFakeCore{key:key,complete:completed})
		if completed && (err!=nil||!f.confirmed) {t.Fatalf("complete signed receipt rejected: %v",err)}
		if !completed && (err==nil||f.confirmed) {t.Fatalf("policy-only proof confirmed as APPLIED: %v",err)}
	}
}

type managedSignedCeilingFake struct {
	message string
}
func (m managedSignedCeilingFake) ApplyWithProof(context.Context, corepolicy.Policy, string, ed25519.PublicKey) ([]byte,error) {
	return nil,errors.New("unexpected legacy policy path")
}
func (m managedSignedCeilingFake) ApplyManagedWithProof(context.Context, corepolicy.Policy, string, ed25519.PublicKey, corepolicy.ManagedOperation) ([]byte,error) {
	return nil,fmt.Errorf("set ElXray runtime policy: %w",status.Error(codes.PermissionDenied,m.message))
}

func TestManagedCeilingRaceNeverAcknowledgesOrCrashesAgent(t *testing.T) {
	key:=ed25519.NewKeyFromSeed(make([]byte,ed25519.SeedSize))
	job:=Job{
		PublicKey:key.Public().(ed25519.PublicKey),
		Operation:uuid.NewString(),NodeID:uuid.NewString(),ResourceID:uuid.NewString(),
		ExecutorID:uuid.NewString(),AuthorityGeneration:9,
		Policy:corepolicy.Policy{ID:"lab",Revision:2,UplinkBps:150,DownlinkBps:180},
		Challenge:"00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff",
	}
	encoded,err:=json.Marshal(job)
	if err!=nil {t.Fatal(err)}
	for _,tc:=range []struct{message string;expected codes.Code}{
		{"managed subscription update exceeds signed Control authority",codes.Unavailable},
		{"untrusted managed signature",codes.PermissionDenied},
	}{
		conn:=&managedFakeConn{job:encoded}
		err:=ApplyNext(context.Background(),conn,managedSignedCeilingFake{message:tc.message})
		if status.Code(err)!=tc.expected {
			t.Fatalf("managed rejection %q changed to %s, want %s: %v",tc.message,status.Code(err),tc.expected,err)
		}
		if conn.confirmed {
			t.Fatalf("unapplied managed policy was confirmed after %q",tc.message)
		}
	}
}
