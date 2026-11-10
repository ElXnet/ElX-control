package corepolicy

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestRetiredCoreProofSameGoldenAsElXray(t *testing.T) {
	g := ProfileGrantIntent{
		Version: 2, Action: "retire",
		OperationID: uuid.MustParse("11111111-1111-4111-8111-111111111111"),
		NodeID: uuid.MustParse("22222222-2222-4222-8222-222222222222"),
		ExecutorID: uuid.MustParse("33333333-3333-4333-8333-333333333333"),
		ResourceID: uuid.MustParse("44444444-4444-4444-8444-444444444444"),
		ProfileID: uuid.MustParse("55555555-5555-4555-8555-555555555555"),
		SubscriptionID: "lab", Email: "device@lab", InboundTag: "vless-reality-01",
		Flow: "xtls-rprx-vision", ProfileGeneration: 2,
		AuthorityGeneration: 9, PolicyRevision: 4,
		NotBefore: 1700000000, NotAfter: 1700000030,
	}
	h := sha256.Sum256(g.Transcript())
	if hex.EncodeToString(h[:]) != "07bb286a26be073e6fe63e002234f3846fb32eace4e4113b4079fd6c36b47908" {
		t.Fatal("ElXray signed RETIRE grant transcript mismatch")
	}
	store := uuid.MustParse("66666666-6666-4666-8666-666666666666")
	boot := uuid.MustParse("77777777-7777-4777-8777-777777777777")
	proof := RetireReceipt{
		Version: 1, OperationID: g.OperationID, ProfileID: g.ProfileID,
		NodeID: g.NodeID, ExecutorID: g.ExecutorID, ResourceID: g.ResourceID,
		StoreID: store, CoreIncarnation: boot,
		AuthorityGeneration: 9, PolicyRevision: 4, RetireGeneration: 2,
		TranscriptSHA256: hex.EncodeToString(h[:]),
	}
	sum := sha256.Sum256(proof.Transcript())
	if hex.EncodeToString(sum[:]) != "531a8623814add61ab52baec1dcab6910e3399fd246c352fe784c53775860c44" {
		t.Fatalf("ElXray signed RETIRED proof transcript mismatch: %x", sum)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	proof.Signature = ed25519.Sign(key, proof.Transcript())
	pub := key.Public().(ed25519.PublicKey)
	if err := VerifyRetireReceipt(proof, g, pub, store, boot); err != nil { t.Fatal(err) }
	if err := VerifyRetireReceipt(proof, g, pub, uuid.New(), boot); !errors.Is(err, ErrRetireProof) {
		t.Fatal("foreign durable store was accepted")
	}
	if err := VerifyRetireReceipt(proof, g, pub, store, uuid.New()); !errors.Is(err, ErrRetireProof) {
		t.Fatal("unknown core incarnation was accepted")
	}
	changed := proof
	changed.RetireGeneration++
	if err := VerifyRetireReceipt(changed, g, pub, store, boot); !errors.Is(err, ErrRetireProof) {
		t.Fatal("forged tombstone generation was accepted")
	}
}
