package corepolicy

import (
	"crypto/ed25519"
	"encoding/json"
	"fmt"
	"testing"
)

func TestManagedAppliedReceiptSignatureAndMutatedBindings(t *testing.T) {
	seed := make([]byte, ed25519.SeedSize)
	seed[0] = 0x11
	key := ed25519.NewKeyFromSeed(seed)
	pub := key.Public().(ed25519.PublicKey)
	op := ManagedOperation{
		OperationID: "11111111-1111-4111-8111-111111111111",
		NodeID: "22222222-2222-4222-8222-222222222222",
		ResourceID: "33333333-3333-4333-8333-333333333333",
		ExecutorID: "44444444-4444-4444-8444-444444444444",
		AuthorityGeneration: 9,
	}
	p := Policy{ID: "lab", Revision: 2, UplinkBps: 90, DownlinkBps: 180}
	evidence := AppliedEvidence{
		Version: 1, OperationID: op.OperationID, NodeID: op.NodeID,
		ResourceID: op.ResourceID, ExecutorID: op.ExecutorID,
		PayloadSHA256: ManagedMutationDigest(p),
		AuthorityGeneration: op.AuthorityGeneration, Revision: p.Revision,
		CoreIncarnation: "55555555-5555-4555-8555-555555555555",
		StoreID: "66666666-6666-4666-8666-666666666666",
		CompletedUnixNanos: 1700000000000000000,
	}
	const challenge = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	transcript := func(v AppliedEvidence) []byte {
		return fmt.Appendf(nil, "elx-applied-operation-v1\n%x\n%s\n%s\n%s\n%s\n%s\n%d\n%d\n%s\n%s\n%d",
			challenge, v.OperationID, v.PayloadSHA256, v.NodeID, v.ExecutorID, v.ResourceID,
			v.AuthorityGeneration, v.Revision, v.CoreIncarnation, v.StoreID, v.CompletedUnixNanos)
	}
	evidence.Signature = ed25519.Sign(key, transcript(evidence))
	check := func(v AppliedEvidence) bool {
		raw, err := json.Marshal(v)
		if err != nil { t.Fatal(err) }
		return VerifyAppliedEvidence(pub, challenge, op, p, raw)
	}
	if !check(evidence) { t.Fatal("valid pinned operation signature rejected") }
	for _, mutate := range []func(*AppliedEvidence){
		func(x *AppliedEvidence) { x.OperationID = x.NodeID },
		func(x *AppliedEvidence) { x.NodeID = x.ExecutorID },
		func(x *AppliedEvidence) { x.ExecutorID = x.ResourceID },
		func(x *AppliedEvidence) { x.ResourceID = x.NodeID },
		func(x *AppliedEvidence) { x.PayloadSHA256 = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" },
		func(x *AppliedEvidence) { x.AuthorityGeneration++ },
		func(x *AppliedEvidence) { x.Revision++ },
		func(x *AppliedEvidence) { x.CoreIncarnation = x.StoreID },
		func(x *AppliedEvidence) { x.StoreID = x.CoreIncarnation },
		func(x *AppliedEvidence) { x.CompletedUnixNanos++ },
		func(x *AppliedEvidence) { x.Signature[0] ^= 1 },
	} {
		changed := evidence
		changed.Signature = append([]byte(nil), evidence.Signature...)
		mutate(&changed)
		if check(changed) { t.Fatalf("altered receipt accepted: %+v", changed) }
	}
	bad, _ := json.Marshal(evidence)
	if VerifyAppliedEvidence(pub, challenge, op, p, append(bad, []byte("true")...)) {
		t.Fatal("multiple JSON documents accepted as a signed receipt")
	}
}
