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

// nextTechnicalInstall is a separate Control-authenticated delivery method.
// An older PREPARE agent cannot accidentally convert its v1 job into AddUser.
// The dispatcher must not central-ACK without a distinct core-signed proof.
func (s *server) nextTechnicalInstall(ctx context.Context,
	_ *emptypb.Empty,
) (*wrapperspb.BytesValue, error) {
	bindings, err := s.authorize(ctx)
	if err != nil {
		return nil, err
	}
	if s.db == nil || len(s.leaseKey) != ed25519.PrivateKeySize {
		return nil, status.Error(codes.FailedPrecondition, "Control technical INSTALL authority unavailable")
	}
	for _, b := range bindings {
		if !validID(b.ExecutorID) {
			continue
		}
		grant, err := journal.NextTechnicalInstall(ctx, s.db,
			b.Target, b.ExecutorID, b.Subscription)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			if errors.Is(err, journal.ErrInvalid) || errors.Is(err, journal.ErrProfileAuthority) {
				return nil, status.Error(codes.FailedPrecondition, "technical INSTALL ledger conflicts with Control")
			}
			return nil, status.Error(codes.Unavailable, "technical INSTALL database unavailable")
		}
		if grant.Version != 2 || grant.Action != "install" ||
			grant.ProfileGeneration != 1 ||
			grant.NodeID.String() != b.Target.NodeID ||
			grant.ResourceID.String() != b.Target.ResourceID ||
			grant.ExecutorID.String() != b.ExecutorID ||
			grant.SubscriptionID != b.Subscription ||
			grant.AuthorityGeneration != uint64(b.Epoch) ||
			grant.NotAfter <= time.Now().UTC().Unix() {
			return nil, status.Error(codes.FailedPrecondition, "technical INSTALL no longer matches signed node authority")
		}
		job := TechnicalProfileJob{
			Grant: grant,
			Signature: ed25519.Sign(s.leaseKey, grant.Transcript()),
		}
		payload, err := json.Marshal(job)
		if err != nil || len(payload) == 0 || len(payload) > 4096 {
			return nil, status.Error(codes.Internal, "cannot encode bounded signed INSTALL job")
		}
		return wrapperspb.Bytes(payload), nil
	}
	return nil, status.Error(codes.NotFound, "no approved technical INSTALL")
}
