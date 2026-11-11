package policytransport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"

	"github.com/ElXnet/ElX-control/internal/elxcontrol/corepolicy"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/journal"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// confirmTechnicalRetire cannot accept a plain agent ACK. PostgreSQL
// independently checks the pinned ElXray signer/store/boot and RETIRE intent.
func (s *server) confirmTechnicalRetire(ctx context.Context,
	request *wrapperspb.BytesValue,
) (*emptypb.Empty, error) {
	bindings, err := s.authorize(ctx)
	if err != nil { return nil, err }
	if s.db == nil || request == nil || len(request.Value) == 0 ||
		len(request.Value) > 4096 || validateUniqueControlJobJSON(request.Value) != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid technical RETIRE receipt")
	}
	var proof corepolicy.RetireReceipt
	decoder := json.NewDecoder(bytes.NewReader(request.Value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&proof); err != nil {
		return nil, status.Error(codes.InvalidArgument, "malformed signed RETIRE evidence")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, status.Error(codes.InvalidArgument, "trailing RETIRE evidence")
	}
	bound := false
	for _, b := range bindings {
		if b.Target.NodeID == proof.NodeID.String() &&
			b.Target.ResourceID == proof.ResourceID.String() &&
			b.ExecutorID == proof.ExecutorID.String() &&
			b.Epoch > 0 && uint64(b.Epoch) == proof.AuthorityGeneration {
			bound = true
			break
		}
	}
	if !bound {
		return nil, status.Error(codes.PermissionDenied, "foreign or superseded RETIRE receipt")
	}
	err = journal.ConfirmTechnicalRetired(ctx, s.db, proof)
	switch {
	case errors.Is(err, corepolicy.ErrRetireProof):
		return nil, status.Error(codes.PermissionDenied, "untrusted core RETIRE signature or store")
	case errors.Is(err, journal.ErrProfileAuthority), errors.Is(err, journal.ErrProfileConflict):
		return nil, status.Error(codes.FailedPrecondition, "RETIRE pending authority or witness mismatch")
	case err != nil:
		return nil, status.Error(codes.Unavailable, "technical RETIRE confirmation unavailable")
	}
	return &emptypb.Empty{}, nil
}
