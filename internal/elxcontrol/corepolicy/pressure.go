package corepolicy

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
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

const (
	pressureEvidenceSize = 120
	pressureMaxRate      = uint64(1 << 40)
)

var (
	ErrPressureStale = errors.New("ElXray pressure sample is stale")
	ErrPressureRestart = errors.New("ElXray pressure core incarnation changed")
	ErrPressureRegression = errors.New("ElXray pressure counters, sequence or policy regressed")
)

// DirectionPressure is one half of the independent upload/download evidence.
// These are cumulative counters and a live gauge, NOT entitlement grants.
type DirectionPressure struct {
	PayloadBytes  uint64
	BlockedCalls  uint64
	BlockedNanos  uint64
	ActiveWaiters uint64
}

// PressureSample is verified, core-signed telemetry for one subscription.
// A caller still MUST bind this to the Control journal's assigned
// node/resource, pinned core incarnation and current applied policy revision
// before allowing it to influence a demand-aware grant.
type PressureSample struct {
	Incarnation uuid.UUID
	Sequence    uint64
	SampledAt   time.Time
	Revision    uint64
	RateUp      uint64
	RateDown    uint64
	Upload      DirectionPressure
	Download    DirectionPressure
}

// ReadPressure uses an unpredictable challenge per RPC and verifies the exact
// signed reply against the provisioned ElXray policy key, never a peer-supplied
// key. This API connects to the protected local ElXray Commander socket.
func (c *Client) ReadPressure(ctx context.Context, subscription string, key ed25519.PublicKey) (PressureSample, error) {
	if subscription == "" || len(subscription) > 1024 || len(key) != ed25519.PublicKeySize {
		return PressureSample{}, errors.New("invalid pressure source")
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return PressureSample{}, err
	}
	challenge := hex.EncodeToString(nonce[:])
	data, err := c.ReadPressureEvidence(ctx, subscription, challenge)
	if err != nil {
		return PressureSample{}, err
	}
	return VerifyPressureEvidence(subscription, challenge, key, data)
}

// ReadPressureEvidence carries opaque signed bytes out of the core. This
// function does NOT authenticate the bytes. Only Control's verification with
// a durable, node-bound key can authorize consumption of the evidence.
func (c *Client) ReadPressureEvidence(ctx context.Context, subscription, challenge string) ([]byte, error) {
	nonce, err := hex.DecodeString(challenge)
	if subscription == "" || len(subscription) > 1024 ||
		err != nil || len(challenge) != 32 || len(nonce) != 16 ||
		hex.EncodeToString(nonce) != challenge {
		return nil, errors.New("invalid signed pressure request")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	ctx = metadata.AppendToOutgoingContext(ctx, "elx-pressure-challenge", challenge)
	var header metadata.MD
	p, err := c.rpc.GetSubscription(ctx, &wire.GetSubscriptionRequest{Id: subscription}, grpc.Header(&header))
	if err != nil {
		return nil, err
	}
	values := header.Get("elx-pressure-bin")
	if p.GetId() != subscription || len(values) != 1 ||
		len(values[0]) != pressureEvidenceSize+ed25519.SignatureSize {
		return nil, errors.New("missing or malformed ElXray signed pressure")
	}
	return []byte(values[0]), nil
}

// VerifyPressureEvidence checks the domain-separated, nonce-bound transcript,
// the signed policy revision and both independent rate counters. The receiver
// must issue a fresh nonce: replaying a signed sample under another nonce
// fails verification. Persistent sequence/high-water checks are additional
// scheduler responsibilities, implemented via ValidatePressureProgress.
func VerifyPressureEvidence(subscription, challenge string, key ed25519.PublicKey, sample []byte) (PressureSample, error) {
	if subscription == "" || len(subscription) > 1024 || len(key) != ed25519.PublicKeySize ||
		len(sample) != pressureEvidenceSize+ed25519.SignatureSize {
		return PressureSample{}, errors.New("invalid pressure evidence binding")
	}
	nonce, err := hex.DecodeString(challenge)
	if err != nil || len(nonce) != 16 || len(challenge) != 32 || hex.EncodeToString(nonce) != challenge {
		return PressureSample{}, errors.New("invalid pressure evidence challenge")
	}
	raw := sample[:pressureEvidenceSize]
	message := fmt.Appendf(nil, "elx-pressure-v1\n%x\n%x\n%x", challenge, subscription, raw)
	if !ed25519.Verify(key, message, sample[pressureEvidenceSize:]) {
		return PressureSample{}, errors.New("ElXray pressure signature does not match pinned core")
	}
	values := make([]uint64, 13)
	for i := range values {
		values[i] = binary.BigEndian.Uint64(raw[16+i*8 : 24+i*8])
	}
	var p PressureSample
	p.Incarnation = uuid.UUID(raw[:16])
	p.Sequence = values[0]
	if values[1] > math.MaxInt64 {
		return PressureSample{}, errors.New("invalid pressure timestamp")
	}
	p.SampledAt = time.Unix(0, int64(values[1])).UTC()
	p.Revision, p.RateUp, p.RateDown = values[2], values[3], values[4]
	p.Upload = DirectionPressure{PayloadBytes: values[5], BlockedCalls: values[6],
		BlockedNanos: values[7], ActiveWaiters: values[8]}
	p.Download = DirectionPressure{PayloadBytes: values[9], BlockedCalls: values[10],
		BlockedNanos: values[11], ActiveWaiters: values[12]}
	if p.Incarnation == uuid.Nil || p.Sequence == 0 || p.Revision == 0 ||
		p.SampledAt.UnixNano() <= 0 ||
		p.RateUp > pressureMaxRate || p.RateDown > pressureMaxRate ||
		(p.RateUp == 0) != (p.RateDown == 0) ||
		p.Upload.PayloadBytes > math.MaxInt64 || p.Download.PayloadBytes > math.MaxInt64 ||
		p.Upload.ActiveWaiters > 1000000 || p.Download.ActiveWaiters > 1000000 {
		return PressureSample{}, errors.New("invalid signed pressure fields")
	}
	now := time.Now()
	if p.SampledAt.After(now.Add(2*time.Second)) || now.Sub(p.SampledAt) > 10*time.Second {
		return PressureSample{}, ErrPressureStale
	}
	return p, nil
}

// ValidatePressureProgress must be called with the most recent durable
// high-watermark for the same entitlement, node and resource. A restarted
// core is never auto-accepted: reconcile the new core identity and policy
// before replacing the previous durable high-watermark.
func ValidatePressureProgress(previous, next PressureSample) error {
	if previous.Incarnation == uuid.Nil || next.Incarnation != previous.Incarnation {
		return ErrPressureRestart
	}
	if next.Sequence <= previous.Sequence ||
		!next.SampledAt.After(previous.SampledAt) ||
		next.Revision < previous.Revision ||
		next.Upload.PayloadBytes < previous.Upload.PayloadBytes ||
		next.Download.PayloadBytes < previous.Download.PayloadBytes ||
		next.Upload.BlockedCalls < previous.Upload.BlockedCalls ||
		next.Download.BlockedCalls < previous.Download.BlockedCalls ||
		next.Upload.BlockedNanos < previous.Upload.BlockedNanos ||
		next.Download.BlockedNanos < previous.Download.BlockedNanos {
		return ErrPressureRegression
	}
	return nil
}
