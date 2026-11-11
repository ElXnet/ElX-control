package policytransport

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"github.com/ElXnet/ElX-control/internal/elxcontrol/corepolicy"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/journal"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// TechnicalProfileJob is only a short-lived, Control-signed *preparation*
// command for the exact provisioned node/executor. It does not contain any
// device proof and may never independently authorize VPN payload.
type TechnicalProfileJob struct {
	Grant corepolicy.ProfileGrantIntent
	Signature []byte
}

func (s *server) nextTechnicalProfile(ctx context.Context,
	_ *emptypb.Empty) (*wrapperspb.BytesValue, error) {
	bindings, err := s.authorize(ctx)
	if err != nil {
		return nil, err
	}
	if s.db == nil || len(s.leaseKey) != ed25519.PrivateKeySize {
		return nil, status.Error(codes.FailedPrecondition, "technical profile authority unavailable")
	}
	for _, b := range bindings {
		// Legacy bindings are not allowed to receive prepared managed users.
		if !validID(b.ExecutorID) {
			continue
		}
		grant, err := journal.NextTechnicalProfile(ctx, s.db,
			b.Target, b.ExecutorID, b.Subscription)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			if errors.Is(err, journal.ErrProfileAuthority) || errors.Is(err, journal.ErrInvalid) {
				return nil, status.Error(codes.FailedPrecondition, "technical profile grant no longer matches Control")
			}
			return nil, status.Error(codes.Unavailable, "technical profile ledger unavailable")
		}
		if grant.AuthorityGeneration != uint64(b.Epoch) ||
			grant.NodeID.String() != b.Target.NodeID ||
			grant.ExecutorID.String() != b.ExecutorID ||
			grant.ResourceID.String() != b.Target.ResourceID ||
			grant.SubscriptionID != b.Subscription ||
			grant.NotAfter <= time.Now().UTC().Unix() {
			return nil, status.Error(codes.FailedPrecondition, "technical profile epoch or executor superseded")
		}
		// Domain-separated from the lease/operation signatures. The
		// private Control key is NEVER sent to the agent or returned in JSON.
		job := TechnicalProfileJob{
			Grant: grant, Signature: ed25519.Sign(s.leaseKey, grant.Transcript()),
		}
		data, err := json.Marshal(job)
		if err != nil {
			return nil, status.Error(codes.Internal, "could not encode signed technical profile")
		}
		if len(data) > 4096 {
			return nil, status.Error(codes.Internal, "technical profile exceeds wire limit")
		}
		return wrapperspb.Bytes(data), nil
	}
	return nil, status.Error(codes.NotFound, "no prepared technical profile")
}
