package policytransport

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/ElXnet/ElX-control/internal/elxcontrol/journal"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// nextTechnicalRetire is independent of PREPARE and INSTALL. An authentic
// revocation may be delivered after the paid entitlement expires, but only
// to the exact mTLS-authenticated node and current executor/resource.
func (s *server) nextTechnicalRetire(ctx context.Context,
	_ *emptypb.Empty,
) (*wrapperspb.BytesValue, error) {
	bindings, err := s.authorize(ctx)
	if err != nil { return nil, err }
	if s.db == nil || len(s.leaseKey) != ed25519.PrivateKeySize {
		return nil, status.Error(codes.FailedPrecondition, "signed retire authority unavailable")
	}
	for _, b := range bindings {
		if !validID(b.ExecutorID) { continue }
		g, err := journal.NextTechnicalRetire(ctx, s.db,
			b.Target, b.ExecutorID, b.Subscription)
		if errors.Is(err, sql.ErrNoRows) { continue }
		if err != nil {
			if errors.Is(err, journal.ErrInvalid) || errors.Is(err, journal.ErrProfileAuthority) {
				return nil, status.Error(codes.FailedPrecondition, "technical RETIRE ledger conflicts with Control")
			}
			return nil, status.Error(codes.Unavailable, "technical RETIRE database unavailable")
		}
		if g.Version != 2 || g.Action != "retire" ||
			g.ProfileGeneration != 2 ||
			g.NodeID.String() != b.Target.NodeID ||
			g.ResourceID.String() != b.Target.ResourceID ||
			g.ExecutorID.String() != b.ExecutorID ||
			g.SubscriptionID != b.Subscription ||
			g.AuthorityGeneration != uint64(b.Epoch) ||
			g.NotAfter <= time.Now().UTC().Unix() {
			return nil, status.Error(codes.FailedPrecondition, "retire no longer matches node authority")
		}
		job := TechnicalProfileJob{Grant: g, Signature: ed25519.Sign(s.leaseKey, g.Transcript())}
		data, err := json.Marshal(job)
		if err != nil || len(data) == 0 || len(data) > 4096 {
			return nil, status.Error(codes.Internal, "cannot encode bounded signed RETIRE job")
		}
		return wrapperspb.Bytes(data), nil
	}
	return nil, status.Error(codes.NotFound, "no approved technical RETIRE")
}
