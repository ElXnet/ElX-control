package corepolicy

import (
	"crypto/sha256"
	"encoding/hex"
	"testing"

	"github.com/google/uuid"
)

func TestProfileGrantV1GoldenMatchesElXray(t *testing.T) {
	g:=ProfileGrantIntent{
		Version:1,Action:"prepare",
		OperationID:uuid.MustParse("11111111-1111-4111-8111-111111111111"),
		NodeID:uuid.MustParse("22222222-2222-4222-8222-222222222222"),
		ExecutorID:uuid.MustParse("33333333-3333-4333-8333-333333333333"),
		ResourceID:uuid.MustParse("44444444-4444-4444-8444-444444444444"),
		ProfileID:uuid.MustParse("55555555-5555-4555-8555-555555555555"),
		SubscriptionID:"lab",Email:"device@lab",InboundTag:"vless-reality-01",
		ProfileGeneration:2,AuthorityGeneration:9,PolicyRevision:4,
		NotBefore:1700000000,NotAfter:1700000030,
	}
	h:=sha256.Sum256(g.Transcript())
	const expected="8282465f046f0dea2b02289253ab1e29cf053742a4fb2a7e4697d3187b4ef1cd"
	if hex.EncodeToString(h[:])!=expected {t.Fatalf("ElXray/Control signed technical grant wire mismatch: %x",h)}
	for _,mutate:=range []func(*ProfileGrantIntent){
		func(x *ProfileGrantIntent){x.OperationID=uuid.New()},
		func(x *ProfileGrantIntent){x.NodeID=uuid.New()},
		func(x *ProfileGrantIntent){x.ExecutorID=uuid.New()},
		func(x *ProfileGrantIntent){x.ResourceID=uuid.New()},
		func(x *ProfileGrantIntent){x.ProfileID=uuid.New()},
		func(x *ProfileGrantIntent){x.SubscriptionID="other"},
		func(x *ProfileGrantIntent){x.Email="other"},
		func(x *ProfileGrantIntent){x.InboundTag="other"},
		func(x *ProfileGrantIntent){x.ProfileGeneration++},
		func(x *ProfileGrantIntent){x.AuthorityGeneration++},
		func(x *ProfileGrantIntent){x.PolicyRevision++},
		func(x *ProfileGrantIntent){x.NotAfter++},
	}{
		altered:=g
		mutate(&altered)
		digest:=sha256.Sum256(altered.Transcript())
		if digest==h {t.Fatalf("modified technical grant retained the signed transcript: %+v",altered)}
	}
}
