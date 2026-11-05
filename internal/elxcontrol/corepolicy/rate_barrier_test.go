package corepolicy

import (
	"bytes"
	"crypto/ed25519"
	"fmt"
	"testing"

	"github.com/google/uuid"
)

func TestRateBarrierTranscriptBindsLedgerRevisionAndSignedLimits(t *testing.T) {
	r:=RateBarrierRequest{
		EntitlementID:uuid.New(),NodeID:uuid.New(),ResourceID:uuid.New(),
		OperationID:uuid.New(),Subscription:"lab",
		Epoch:3,Revision:7,CoreRevision:8,Up:25,Down:45,
	}
	proof:=BarrierTranscript(r)
	expected:=fmt.Appendf(nil,"elx-rate-barrier-v1\n%s\n%s\n%s\n%s\n%d\n%d\n%d\n%d",
		r.EntitlementID,r.NodeID,r.ResourceID,r.OperationID,
		r.Epoch,r.Revision,r.Up,r.Down)
	if !bytes.Equal(proof,expected){t.Fatal("rate grant barrier transcript mismatch")}
	pub,key,err:=ed25519.GenerateKey(nil)
	if err!=nil{t.Fatal(err)}
	sig:=ed25519.Sign(key,proof)
	if !ed25519.Verify(pub,proof,sig){t.Fatal("valid barrier proof failed verification")}
	changed:=r
	changed.NodeID=uuid.New()
	if ed25519.Verify(pub,BarrierTranscript(changed),sig){
		t.Fatal("barrier could release a different node grant")
	}
	changed=r
	changed.Up++
	if ed25519.Verify(pub,BarrierTranscript(changed),sig){
		t.Fatal("barrier accepted release of unproven speed")
	}
	changed=r
	changed.OperationID=uuid.New()
	if ed25519.Verify(pub,BarrierTranscript(changed),sig){
		t.Fatal("barrier replayed into a new operation")
	}
}
