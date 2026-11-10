package policytransport

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/google/uuid"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/journal"
)

func TestControlLeaseV3GoldenTranscriptAndAdversarialSignature(t *testing.T) {
	ids := [3]uuid.UUID{
		uuid.MustParse("11111111-1111-4111-8111-111111111111"),
		uuid.MustParse("22222222-2222-4222-8222-222222222222"),
		uuid.MustParse("33333333-3333-4333-8333-333333333333"),
	}
	ticket := Lease{
		Version: 3, NodeID: ids[0], ResourceID: ids[1], ExecutorID: ids[2],
		Subscription: "entitlement-A", Sequence: 7, NotBefore: 1700000000,
		NotAfter: 1700000015, CeilingUp: 12500000, CeilingDown: 6250000,
		AuthorityGeneration: 9,
	}
	data := ticket.transcript()
	sum := sha256.Sum256(data)
	if hex.EncodeToString(sum[:]) != "ae629b1897c95b9faac7fb8204e18f58c90abdcfd6ff8dcc6bdd3b9c7fa177b7" {
		t.Fatalf("Control issuer transcript differs from pinned ElXray consumer: %x", sum)
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x11}, ed25519.SeedSize))
	sig := ed25519.Sign(key, data)
	pub := key.Public().(ed25519.PublicKey)
	if !ed25519.Verify(pub, data, sig) {
		t.Fatal("Control issuer produced invalid signature")
	}
	for _, change := range []func(*Lease){
		func(x *Lease) { x.Version = 2 },
		func(x *Lease) { x.NodeID = ids[1] },
		func(x *Lease) { x.ResourceID = ids[0] },
		func(x *Lease) { x.ExecutorID = ids[0] },
		func(x *Lease) { x.AuthorityGeneration++ },
		func(x *Lease) { x.Subscription += "-other" },
		func(x *Lease) { x.Sequence++ },
		func(x *Lease) { x.NotAfter++ },
		func(x *Lease) { x.CeilingUp++ },
		func(x *Lease) { x.CeilingDown++ },
	} {
		changed := ticket
		change(&changed)
		if ed25519.Verify(pub, changed.transcript(), sig) {
			t.Fatalf("Control v3 transcript allows an altered binding: %+v", changed)
		}
	}
}

func TestManagedBindingRequiresCanonicalExecutorWhenIssued(t *testing.T) {
	b := Binding{
		Target: journal.Target{
			NodeID: "11111111-1111-4111-8111-111111111111",
			ResourceID: "22222222-2222-4222-8222-222222222222",
		},
		Subscription: "entitlement-A", Epoch: 9,
		PublicKey: make(ed25519.PublicKey, ed25519.PublicKeySize),
	}
	b.ExecutorID = "33333333-3333-4333-8333-333333333333"
	if !b.Valid() {
		t.Fatal("valid executor binding rejected")
	}
	b.ExecutorID = "NOT-A-UUID"
	if b.Valid() {
		t.Fatal("invalid executor identity accepted by trusted manifest")
	}
}

func TestTwoSignedControlSequencesMayShareExactAbsoluteExpiry(t *testing.T) {
	// Control issues sequences at nanosecond resolution, but the signed
	// NotAfter deadline has second resolution. Distinct legitimate tickets
	// frequently carry exactly the same expiry. The core must check the
	// monotonically higher signed sequence, not require a later expiration.
	base := Lease{
		Version:             3,
		NodeID:              uuid.MustParse("11111111-1111-4111-8111-111111111111"),
		ResourceID:          uuid.MustParse("22222222-2222-4222-8222-222222222222"),
		ExecutorID:          uuid.MustParse("33333333-3333-4333-8333-333333333333"),
		Subscription:        "lab",
		AuthorityGeneration: 9,
		Sequence:            1700000000000000001,
		NotBefore:           1700000000,
		NotAfter:            1700000015,
		CeilingUp:           250000,
		CeilingDown:         250000,
	}
	next := base
	next.Sequence++
	if next.NotAfter != base.NotAfter || next.Sequence <= base.Sequence {
		t.Fatal("fixture does not represent second-resolution Control leases")
	}
	key := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{0x22}, ed25519.SeedSize))
	pub := key.Public().(ed25519.PublicKey)
	firstSig := ed25519.Sign(key, base.transcript())
	secondSig := ed25519.Sign(key, next.transcript())
	if bytes.Equal(firstSig, secondSig) ||
		!ed25519.Verify(pub, base.transcript(), firstSig) ||
		!ed25519.Verify(pub, next.transcript(), secondSig) ||
		ed25519.Verify(pub, next.transcript(), firstSig) {
		t.Fatal("same-expiry signed Control lease sequence lost anti-replay binding")
	}
}
