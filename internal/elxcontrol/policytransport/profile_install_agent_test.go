package policytransport

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"testing"
	"time"

	"github.com/ElXnet/ElX-control/internal/elxcontrol/corepolicy"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/journal"
	"github.com/google/uuid"
)

type stage4InstallFake struct {
	expected corepolicy.TechnicalPrepared
	calls    int
}

func (f *stage4InstallFake) InstallTechnicalProfile(_ context.Context, _ []byte) (corepolicy.TechnicalPrepared, error) {
	f.calls++
	return f.expected, nil
}

func (f *stage4InstallFake) ReadbackTechnicalProfile(_ context.Context, _ string) (corepolicy.TechnicalPrepared, error) {
	return f.expected, nil
}

func TestAgentVerifiesSignedInstallBeforeInvokingCore(t *testing.T) {
	now := time.Now().UTC().Unix()
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	grant := corepolicy.ProfileGrantIntent{
		Version: 2, Action: "install",
		OperationID: uuid.New(), NodeID: uuid.New(), ExecutorID: uuid.New(),
		ResourceID: uuid.New(), ProfileID: uuid.New(),
		SubscriptionID: "lab", Email: "device@lab", InboundTag: "vless-reality-01",
		Flow: "xtls-rprx-vision", ProfileGeneration: 1,
		AuthorityGeneration: 9, PolicyRevision: 1,
		NotBefore: now - 2, NotAfter: now + 30,
	}
	digest := sha256.Sum256(grant.Transcript())
	fake := &stage4InstallFake{expected: corepolicy.TechnicalPrepared{
		ProfileID: grant.ProfileID.String(), InstallOperationID: grant.OperationID.String(),
		NodeID: grant.NodeID.String(), ExecutorID: grant.ExecutorID.String(),
		ResourceID: grant.ResourceID.String(), SubscriptionID: grant.SubscriptionID,
		Email: grant.Email, InboundTag: grant.InboundTag,
		ProfileGeneration: grant.ProfileGeneration,
		AuthorityGeneration: grant.AuthorityGeneration,
		PolicyRevision: grant.PolicyRevision, Flow: grant.Flow,
		InstallTranscriptSHA256: hex.EncodeToString(digest[:]), Phase: "INSTALLED",
	}}
	binding := Binding{
		Target: journal.Target{NodeID: grant.NodeID.String(), ResourceID: grant.ResourceID.String()},
		ExecutorID: grant.ExecutorID.String(), Subscription: grant.SubscriptionID,
		Epoch: 9, PublicKey: key.Public().(ed25519.PublicKey),
	}
	encode := func(g corepolicy.ProfileGrantIntent, sign bool) []byte {
		t.Helper()
		var signature []byte
		if sign {
			signature = ed25519.Sign(key, g.Transcript())
		}
		raw, err := json.Marshal(TechnicalProfileJob{Grant: g, Signature: signature})
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	raw := encode(grant, true)
	installed, err := VerifyAndInstallTechnicalProfile(context.Background(),
		raw, fake, []Binding{binding}, key.Public().(ed25519.PublicKey))
	if err != nil || installed != fake.expected || fake.calls != 1 {
		t.Fatalf("valid install rejected or mismatched: %+v %v calls=%d", installed, err, fake.calls)
	}
	for name, malformed := range map[string][]byte{
		"tampered-flow": func() []byte { x := grant; x.Flow = ""; return encode(x, false) }(),
		"wrong-signature": encode(grant, false),
		"duplicate-member": append(append([]byte(nil), raw[:len(raw)-1]...), []byte(`,"grant":{}}`)...),
		"trailing-document": append(append([]byte(nil), raw...), []byte("true")...),
		"downgrade-v1": func() []byte { x := grant; x.Version = 1; return encode(x, true) }(),
		"foreign-executor": func() []byte { x := grant; x.ExecutorID = uuid.New(); return encode(x, true) }(),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := VerifyAndInstallTechnicalProfile(context.Background(), malformed,
				fake, []Binding{binding}, key.Public().(ed25519.PublicKey)); err == nil {
				t.Fatal("untrusted INSTALL accepted")
			}
		})
	}
	if fake.calls != 1 {
		t.Fatalf("untrusted work reached local VLESS core: %d", fake.calls)
	}
	fake.expected.Flow = ""
	if _, err := VerifyAndInstallTechnicalProfile(context.Background(), raw,
		fake, []Binding{binding}, key.Public().(ed25519.PublicKey)); err == nil {
		t.Fatal("forged/incorrect installed flow readback accepted")
	}
}
