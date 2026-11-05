package corepolicy

import (
	"context"
	"crypto/ed25519"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math"
	"time"

	"github.com/google/uuid"
	wire "github.com/ElXnet/ElX-control/internal/elxcontrol/corepolicy/wire"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

const leaseAcceptanceSize = 88

var ErrLeaseNotActive = errors.New("core has no current verified Control lease")

// AcceptedLease proves a Control-signed lease has actually been installed
// into the pinned ElXray limiter. Issuance and agent RPC success alone do not
// prove this. It never authorizes additional rate grant or physical devices.
type AcceptedLease struct {
	Incarnation uuid.UUID
	NodeID uuid.UUID
	Sequence int64
	ExpiresAt time.Time
	CeilingUp int64
	CeilingDown int64
	Revision uint64
	AppliedUp int64
	AppliedDown int64
}

// ReadLeaseAcceptanceEvidence reads an opaque signature from the private,
// protected ElXray Commander socket. The remote node is NOT trusted to choose
// the public key; that key comes only from Control's assigned core identity.
func (c *Client) ReadLeaseAcceptanceEvidence(ctx context.Context, subscription, challenge string) ([]byte,error) {
	nonce, err := hex.DecodeString(challenge)
	if subscription == "" || len(subscription) > 1024 ||
		err != nil || len(challenge) != 32 || len(nonce) != 16 ||
		hex.EncodeToString(nonce) != challenge {
		return nil, errors.New("invalid lease-acceptance challenge")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, "elx-lease-accept-challenge", challenge)
	var header metadata.MD
	p, err := c.rpc.GetSubscription(ctx, &wire.GetSubscriptionRequest{Id:subscription},
		grpc.Header(&header))
	if err != nil { return nil,err }
	values := header.Get("elx-lease-accept-bin")
	if p.GetId() != subscription || len(values) != 1 ||
		len(values[0]) != leaseAcceptanceSize+ed25519.SignatureSize {
		return nil, errors.New("missing or malformed signed core lease acceptance")
	}
	return []byte(values[0]), nil
}

// VerifyLeaseAcceptance validates the core-signed transcript against the
// pinned public key, subscription and a fresh Control challenge. The caller
// must additionally verify the authenticated mTLS node ID, expected core
// incarnation, exact journal target, current policy revision and the
// entitlement's FUP limits *inside a durable transaction*.
func VerifyLeaseAcceptance(subscription, challenge string, key ed25519.PublicKey,
	data []byte, now time.Time) (AcceptedLease,error) {
	var out AcceptedLease
	nonce, err := hex.DecodeString(challenge)
	if subscription == "" || len(subscription)>1024 ||
		err!=nil || len(challenge)!=32 || len(nonce)!=16 ||
		hex.EncodeToString(nonce)!=challenge ||
		len(key)!=ed25519.PublicKeySize ||
		len(data)!=leaseAcceptanceSize+ed25519.SignatureSize ||
		now.IsZero() {
		return out,ErrLeaseNotActive
	}
	raw:=data[:leaseAcceptanceSize]
	transcript:=fmt.Appendf(nil,"elx-lease-accept-v1\n%x\n%x\n%x",challenge,subscription,raw)
	if !ed25519.Verify(key,transcript,data[leaseAcceptanceSize:]) {
		return out,ErrLeaseNotActive
	}
	out.Incarnation=uuid.UUID(raw[:16])
	out.NodeID=uuid.UUID(raw[16:32])
	values:=[7]uint64{}
	for i:=range values{
		values[i]=binary.BigEndian.Uint64(raw[32+i*8:40+i*8])
	}
	if values[0]>math.MaxInt64 || values[1]>math.MaxInt64 ||
		values[2]>math.MaxInt64 || values[3]>math.MaxInt64 ||
		values[4]>math.MaxInt64 || values[5]>math.MaxInt64 || values[6]>math.MaxInt64 {
		return AcceptedLease{},ErrLeaseNotActive
	}
	out.Sequence=int64(values[0])
	out.ExpiresAt=time.Unix(int64(values[1]),0).UTC()
	out.CeilingUp,out.CeilingDown=int64(values[2]),int64(values[3])
	out.Revision=values[4]
	out.AppliedUp,out.AppliedDown=int64(values[5]),int64(values[6])
	if out.Incarnation==uuid.Nil || out.NodeID==uuid.Nil || out.Sequence<=0 ||
		out.CeilingUp<=0 || out.CeilingUp>1<<40 ||
		out.CeilingDown<=0 || out.CeilingDown>1<<40 ||
		out.Revision==0 || out.AppliedUp<=0 || out.AppliedDown<=0 ||
		out.AppliedUp>out.CeilingUp || out.AppliedDown>out.CeilingDown ||
		!out.ExpiresAt.After(now.Add(2*time.Second)) ||
		out.ExpiresAt.After(now.Add(30*time.Second)) {
		return AcceptedLease{},ErrLeaseNotActive
	}
	return out,nil
}
