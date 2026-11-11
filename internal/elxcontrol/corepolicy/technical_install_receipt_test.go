package corepolicy

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/google/uuid"
)

func TestCoreSignedTechnicalInstallProofGoldenAndWitness(t *testing.T) {
	grant := ProfileGrantIntent{
		Version: 2, Action: "install",
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
	hash := sha256.Sum256(grant.Transcript())
	store := uuid.MustParse("66666666-6666-4666-8666-666666666666")
	boot := uuid.MustParse("77777777-7777-4777-8777-777777777777")
	proof := InstallReceipt{
		Version: 1, OperationID: grant.OperationID, ProfileID: grant.ProfileID,
		NodeID: grant.NodeID, ExecutorID: grant.ExecutorID, ResourceID: grant.ResourceID,
		StoreID: store, CoreIncarnation: boot,
		AuthorityGeneration: 9, PolicyRevision: 4,
		TranscriptSHA256: hex.EncodeToString(hash[:]),
	}
	sum := sha256.Sum256(proof.Transcript())
	const golden = "d67adcec0bc268b849ff498f4e9821865698c823c62f107d2a6fe5f3c91fb253"
	if hex.EncodeToString(sum[:]) != golden {
		t.Fatalf("Control/core technical installed proof transcript drift: %x", sum)
	}
	key := ed25519.NewKeyFromSeed(make([]byte, ed25519.SeedSize))
	proof.Signature = ed25519.Sign(key, proof.Transcript())
	pub := key.Public().(ed25519.PublicKey)
	if err := VerifyInstallReceipt(proof, grant, pub, store, boot); err != nil {
		t.Fatalf("authentic installed evidence rejected: %v", err)
	}
	for _, invalid := range []struct {
		p InstallReceipt
		store uuid.UUID
		boot uuid.UUID
	}{
		{p: proof, store: uuid.New(), boot: boot},
		{p: proof, store: store, boot: uuid.New()},
		{p: func() InstallReceipt { c := proof; c.PolicyRevision++; return c }(), store: store, boot: boot},
		{p: func() InstallReceipt { c := proof; c.Signature = nil; return c }(), store: store, boot: boot},
	} {
		if err := VerifyInstallReceipt(invalid.p, grant, pub, invalid.store, invalid.boot); !errors.Is(err, ErrInstallProof) {
			t.Fatal("mismatched store/boot/evidence passed Control")
		}
	}
}
