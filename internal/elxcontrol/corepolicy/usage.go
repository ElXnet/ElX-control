package corepolicy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	wire "github.com/ElXnet/ElX-control/internal/elxcontrol/corepolicy/wire"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

type Usage struct {
	Incarnation uuid.UUID
	Sequence    int64
	SampledAt   time.Time
	UpBytes     int64
	DownBytes   int64
}

// ReadUsage uses a fresh challenge and the assigned core's pinned key so an
// old sample or a different local process cannot impersonate the core.
func (c *Client) ReadUsage(ctx context.Context, id string, key ed25519.PublicKey) (Usage, error) {
	if id == "" || len(key) != ed25519.PublicKeySize {
		return Usage{}, errors.New("invalid usage binding")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return Usage{}, err
	}
	challenge := hex.EncodeToString(nonce[:])
	receipt, err := c.ReadUsageEvidence(ctx, id, challenge)
	if err != nil {
		return Usage{}, err
	}
	return VerifyUsageEvidence(id, challenge, key, receipt)
}

// ReadUsageEvidence requests raw, nonce-bound signed cumulative counters from
// the local ElXray. ONLY the receiving Control can validate the pinned core key
// and decide which accounting stream this belongs to. Never trust this evidence
// before VerifyUsageEvidence succeeds against Control's durable identity.
func (c *Client) ReadUsageEvidence(ctx context.Context, id, challenge string) ([]byte, error) {
	nonce, err := hex.DecodeString(challenge)
	if len(id) == 0 || len(id) > 1024 || err != nil || len(challenge) != 32 || len(nonce) != 16 ||
		hex.EncodeToString(nonce) != challenge {
		return nil, errors.New("invalid signed usage request")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, "elx-usage-challenge", challenge)
	var header metadata.MD
	p, err := c.rpc.GetSubscription(ctx, &wire.GetSubscriptionRequest{Id: id}, grpc.Header(&header))
	if err != nil {
		return nil, err
	}
	values := header.Get("elx-usage-bin")
	if p.GetId() != id || len(values) != 1 || len(values[0]) != 48+ed25519.SignatureSize {
		return nil, errors.New("missing or malformed ElXray signed usage")
	}
	return []byte(values[0]), nil
}

// VerifyUsageEvidence verifies the exact wire transcript signed by ElXray,
// independent of the node that carried it over mTLS. The challenge must be
// issued by Control for the assigned subscription and consumed only once.
func VerifyUsageEvidence(id, challenge string, key ed25519.PublicKey, sample []byte) (Usage, error) {
	return verifyUsage(id, challenge, key, sample)
}

func verifyUsage(id, challenge string, key ed25519.PublicKey, sample []byte) (Usage, error) {
	const size = 48
	if len(sample) != size+ed25519.SignatureSize {
		return Usage{}, errors.New("invalid ElXray usage size")
	}
	data := sample[:size]
	message := fmt.Appendf(nil, "elx-usage-v1\n%x\n%x\n%x", challenge, id, data)
	if len(key) != ed25519.PublicKeySize || !ed25519.Verify(key, message, sample[size:]) {
		return Usage{}, errors.New("ElXray usage signature does not match assigned core")
	}
	u := Usage{
		Incarnation: uuid.UUID(data[:16]),
		Sequence:    int64(binary.BigEndian.Uint64(data[16:24])),
		SampledAt:   time.Unix(0, int64(binary.BigEndian.Uint64(data[24:32]))).UTC(),
		UpBytes:     int64(binary.BigEndian.Uint64(data[32:40])),
		DownBytes:   int64(binary.BigEndian.Uint64(data[40:48])),
	}
	if u.Incarnation == uuid.Nil || u.Sequence <= 0 || u.SampledAt.UnixNano() <= 0 || u.UpBytes < 0 || u.DownBytes < 0 {
		return Usage{}, errors.New("invalid ElXray usage values")
	}
	return u, nil
}
