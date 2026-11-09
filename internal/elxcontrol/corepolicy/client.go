// Package corepolicy applies and reads back local ElXray runtime policies.
package corepolicy

import (
	"context"
	"crypto/sha256"
	"crypto/ed25519"
	"encoding/hex"
	"strconv"
	"errors"
	"fmt"
	"math"
	"net"
	"github.com/google/uuid"
	"path/filepath"
	"time"

	wire "github.com/ElXnet/ElX-control/internal/elxcontrol/corepolicy/wire"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/proto"
)

type Client struct {
	conn *grpc.ClientConn
	rpc  wire.SubscriptionServiceClient
}

// Open connects to a local socket owned by the node supervisor. The socket
// and its parent directory must be protected by operating-system permissions.
func Open(path string) (*Client, error) {
	if !filepath.IsAbs(path) {
		return nil, errors.New("absolute ElXray socket path required")
	}
	conn, err := grpc.NewClient("unix://"+path, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	return &Client{conn: conn, rpc: wire.NewSubscriptionServiceClient(conn)}, nil
}

// OpenLoopback is for isolated hosts and local integration tests. Commander
// on TCP has no peer authentication beyond locality.
func OpenLoopback(address string) (*Client, error) {
	host, _, err := net.SplitHostPort(address)
	if err != nil || !net.ParseIP(host).IsLoopback() {
		return nil, errors.New("literal loopback ElXray address required")
	}
	conn, err := grpc.NewClient(address, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		return nil, err
	}
	return &Client{conn: conn, rpc: wire.NewSubscriptionServiceClient(conn)}, nil
}

func (c *Client) Close() error { return c.conn.Close() }

// ManagedOperation is issued by the trusted Control journal and pinned
// core-executor binding; it is not extracted from a VPN client or request body.
type ManagedOperation struct {
	OperationID string
	NodeID string
	ExecutorID string
	ResourceID string
	AuthorityGeneration uint64
}

type Policy struct {
	ID          string
	Revision    uint64
	UplinkBps   uint64
	DownlinkBps uint64
	Disabled    bool
}

// Apply checks the live policy after the RPC. Its result only proves live
// state and must never be used as a durable application receipt.
func (c *Client) Apply(ctx context.Context, desired Policy) error {
	_, err := c.apply(ctx, desired, "", nil, nil)
	return err
}

// ApplyWithProof requires a signature produced by durable ElXray readback.
func (c *Client) ApplyWithProof(ctx context.Context, desired Policy, challenge string, publicKey ed25519.PublicKey) ([]byte, error) {
	if challenge == "" || len(challenge) > 128 || len(publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("invalid policy challenge")
	}
	return c.apply(ctx, desired, challenge, publicKey, nil)
}

// ApplyManagedWithProof requires the core to atomically journal this exact
// Control operation before persisting/updating the live limiter. A signed
// policy readback is accepted only after that journal reached APPLIED.
func (c *Client) ApplyManagedWithProof(ctx context.Context, desired Policy, challenge string,
	publicKey ed25519.PublicKey, operation ManagedOperation) ([]byte, error) {
	for _, id := range []string{operation.OperationID, operation.NodeID, operation.ResourceID, operation.ExecutorID} {
		parsed, err := uuid.Parse(id)
		if err != nil || parsed == uuid.Nil || parsed.String() != id {
			return nil, errors.New("invalid managed Control operation identity")
		}
	}
	if operation.AuthorityGeneration == 0 {
		return nil, errors.New("managed operation authority generation required")
	}
	if challenge == "" || len(challenge) > 128 || len(publicKey) != ed25519.PublicKeySize {
		return nil, errors.New("invalid signed managed policy challenge")
	}
	return c.apply(ctx, desired, challenge, publicKey, &operation)
}

func (c *Client) apply(ctx context.Context, desired Policy, challenge string, publicKey ed25519.PublicKey, operation *ManagedOperation) ([]byte, error) {
	if desired.ID == "" || desired.Revision < 2 || desired.Revision > math.MaxInt64 ||
		desired.UplinkBps == 0 || desired.DownlinkBps == 0 {
		return nil, errors.New("invalid runtime policy")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	if challenge != "" {
		// Require durable mode before changing live state.
		ctx = metadata.AppendToOutgoingContext(ctx, "elx-policy-challenge", challenge)
		if _, _, err := c.readProof(ctx, desired.ID, challenge, publicKey); err != nil {
			return nil, err
		}
	}
	if operation != nil {
		transcript := fmt.Appendf(nil, "elx-managed-update-v1\n%s\n%d\n%d\n%d\n%d\n%t",
			desired.ID, desired.Revision-1, desired.Revision, desired.UplinkBps, desired.DownlinkBps, desired.Disabled)
		digest := sha256.Sum256(transcript)
		ctx = metadata.AppendToOutgoingContext(ctx,
			"elx-op-id", operation.OperationID,
			"elx-op-node", operation.NodeID,
			"elx-op-executor", operation.ExecutorID,
			"elx-op-resource", operation.ResourceID,
			"elx-op-generation", strconv.FormatUint(operation.AuthorityGeneration, 10),
			"elx-op-hash", hex.EncodeToString(digest[:]),
		)
	}
	_, err := c.rpc.SetSubscription(ctx, &wire.SetSubscriptionRequest{
		Id: desired.ID, ExpectedRevision: desired.Revision - 1, Revision: desired.Revision,
		UplinkBps: proto.Uint64(desired.UplinkBps), DownlinkBps: proto.Uint64(desired.DownlinkBps),
		Disabled: proto.Bool(desired.Disabled),
	})
	if err != nil {
		return nil, fmt.Errorf("set ElXray runtime policy: %w", err)
	}
	var policy *wire.Subscription
	var proof []byte
	if challenge == "" {
		policy, err = c.rpc.GetSubscription(ctx, &wire.GetSubscriptionRequest{Id: desired.ID})
	} else {
		policy, proof, err = c.readProof(ctx, desired.ID, challenge, publicKey)
	}
	if err != nil {
		return nil, fmt.Errorf("read ElXray runtime policy: %w", err)
	}
	if policy.GetId() != desired.ID || policy.GetRevision() != desired.Revision ||
		policy.GetUplinkBps() != desired.UplinkBps || policy.GetDownlinkBps() != desired.DownlinkBps ||
		policy.GetDisabled() != desired.Disabled {
		return nil, errors.New("ElXray runtime policy readback mismatch")
	}
	return proof, nil
}

func (c *Client) readProof(ctx context.Context, id, challenge string, key ed25519.PublicKey) (*wire.Subscription, []byte, error) {
	var header metadata.MD
	policy, err := c.rpc.GetSubscription(ctx, &wire.GetSubscriptionRequest{Id: id}, grpc.Header(&header))
	if err != nil {
		return nil, nil, err
	}
	values := header.Get("elx-policy-proof")
	if len(values) != 1 {
		return nil, nil, errors.New("missing durable ElXray proof")
	}
	proof, err := hex.DecodeString(values[0])
	if err != nil || len(proof) != ed25519.SignatureSize {
		return nil, nil, errors.New("invalid durable ElXray proof")
	}
	if policy.GetId() != id || !VerifyProof(key, challenge, Policy{
		ID: policy.GetId(), Revision: policy.GetRevision(), UplinkBps: policy.GetUplinkBps(),
		DownlinkBps: policy.GetDownlinkBps(), Disabled: policy.GetDisabled(),
	}, proof) {
		return nil, nil, errors.New("ElXray durable signature does not match assigned core")
	}
	return policy, proof, nil
}

// VerifyProof checks the Ed25519 readback format implemented by ElXray.
func VerifyProof(key ed25519.PublicKey, challenge string, p Policy, proof []byte) bool {
	message := fmt.Appendf(nil, "elx-policy-v1\n%x\n%x\n%d\n%d\n%d\n%t",
		challenge, p.ID, p.Revision, p.UplinkBps, p.DownlinkBps, p.Disabled)
	return len(key) == ed25519.PublicKeySize && ed25519.Verify(key, message, proof)
}
