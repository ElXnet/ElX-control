package policytransport

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/ElXnet/ElX-control/internal/elxcontrol/corepolicy"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/journal"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type profileTestConn struct {
	value []byte
	err error
}

func (c *profileTestConn) Invoke(_ context.Context, method string,
	_ any, reply any, _ ...grpc.CallOption) error {
	if method != "/"+serviceName+"/TechnicalProfileNext" {
		return status.Error(codes.Unimplemented, "unexpected method")
	}
	if c.err != nil {
		return c.err
	}
	reply.(*wrapperspb.BytesValue).Value = append([]byte(nil), c.value...)
	return nil
}

func (*profileTestConn) NewStream(context.Context, *grpc.StreamDesc,
	string, ...grpc.CallOption) (grpc.ClientStream, error) {
	return nil, status.Error(codes.Unimplemented, "stream not supported")
}

type profileTestCore struct {
	profile corepolicy.TechnicalPrepared
	prepared, readbacks int
}

func (c *profileTestCore) PrepareTechnicalProfile(_ context.Context,
	_ []byte) (corepolicy.TechnicalPrepared, error) {
	c.prepared++
	return c.profile, nil
}

func (c *profileTestCore) ReadbackTechnicalProfile(_ context.Context,
	_ string) (corepolicy.TechnicalPrepared, error) {
	c.readbacks++
	return c.profile, nil
}

func TestTechnicalProfileAgentValidatesControlSignatureAndExactScope(t *testing.T) {
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	corePublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	node, resource, executor := uuid.New(), uuid.New(), uuid.New()
	now := time.Now().UTC().Unix()
	grant := corepolicy.ProfileGrantIntent{
		Version: 1, Action: "prepare", OperationID: uuid.New(),
		NodeID: node, ResourceID: resource, ExecutorID: executor,
		ProfileID: uuid.New(), SubscriptionID: "lab", Email: "lab@device",
		InboundTag: "vless-reality-01", ProfileGeneration: 1,
		AuthorityGeneration: 9, PolicyRevision: 1,
		NotBefore: now - 2, NotAfter: now + 20,
	}
	binding := Binding{
		Target: journal.Target{NodeID: node.String(), ResourceID: resource.String()},
		Subscription: grant.SubscriptionID, ExecutorID: executor.String(),
		Epoch: 9, PublicKey: corePublic,
	}
	digest := sha256.Sum256(grant.Transcript())
	expected := corepolicy.TechnicalPrepared{
		ProfileID: grant.ProfileID.String(), OperationID: grant.OperationID.String(),
		NodeID: node.String(), ResourceID: resource.String(),
		ExecutorID: executor.String(), SubscriptionID: "lab",
		Email: grant.Email, InboundTag: grant.InboundTag,
		ProfileGeneration: 1, AuthorityGeneration: 9,
		PolicyRevision: 1, TranscriptSHA256: hex.EncodeToString(digest[:]),
		Phase: "PREPARED",
	}
	encode := func(g corepolicy.ProfileGrantIntent, signature []byte) []byte {
		t.Helper()
		raw, err := json.Marshal(TechnicalProfileJob{Grant: g, Signature: signature})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	originalSig := ed25519.Sign(private, grant.Transcript())
	valid := encode(grant, originalSig)
	verifiedCore := &profileTestCore{profile: expected}
	if err := ApplyTechnicalPreparation(context.Background(),
		&profileTestConn{value: valid}, verifiedCore,
		[]Binding{binding}, public); err != nil {
		t.Fatalf("signed technical preparation was rejected: %v", err)
	}
	if verifiedCore.prepared != 1 || verifiedCore.readbacks != 1 {
		t.Fatal("core durability was not checked before reporting preparation")
	}
	tests := []struct {
		name string
		grant corepolicy.ProfileGrantIntent
		sig []byte
		bindings []Binding
		expectedCode codes.Code
	}{
		{"tampered-signature", grant, ed25519.Sign(private, []byte("wrong")), []Binding{binding}, codes.PermissionDenied},
		{"foreign-executor", func() corepolicy.ProfileGrantIntent { g:=grant;g.ExecutorID=uuid.New();return g }(), nil, []Binding{binding}, codes.PermissionDenied},
		{"expired", func() corepolicy.ProfileGrantIntent { g:=grant;g.NotBefore=now-60;g.NotAfter=now-40;return g }(), nil, []Binding{binding}, codes.PermissionDenied},
		{"unassigned", grant, originalSig, []Binding{{Target: journal.Target{NodeID: uuid.NewString(), ResourceID: resource.String()}, Subscription: "lab", ExecutorID: executor.String(), Epoch: 9, PublicKey: corePublic}}, codes.PermissionDenied},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			sig := tt.sig
			if sig == nil {
				sig = ed25519.Sign(private, tt.grant.Transcript())
			}
			stub := &profileTestCore{profile: expected}
			err := ApplyTechnicalPreparation(context.Background(),
				&profileTestConn{value: encode(tt.grant, sig)}, stub,
				tt.bindings, public)
			if status.Code(err) != tt.expectedCode {
				t.Fatalf("unexpected result: %v", err)
			}
			if stub.prepared != 0 || stub.readbacks != 0 {
				t.Fatal("untrusted signed job reached the local core")
			}
		})
	}
	wrongReadback := &profileTestCore{profile: expected}
	wrongReadback.profile.TranscriptSHA256 = hex.EncodeToString(make([]byte, 32))
	if status.Code(ApplyTechnicalPreparation(context.Background(),
		&profileTestConn{value: valid}, wrongReadback,
		[]Binding{binding}, public)) != codes.FailedPrecondition {
		t.Fatal("tampered core readback accepted as the signed profile")
	}
	if status.Code(ApplyTechnicalPreparation(context.Background(),
		&profileTestConn{err: status.Error(codes.NotFound, "no intent")},
		&profileTestCore{}, []Binding{binding}, public)) != codes.NotFound {
		t.Fatal("no prepared profile must remain NotFound, not success")
	}
}
