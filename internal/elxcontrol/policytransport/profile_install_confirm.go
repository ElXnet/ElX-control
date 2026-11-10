package policytransport

import (
	"bytes"
	"context"
	"database/sql"
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

// confirmTechnicalInstall only accepts a proof signed by the actual ElXray
// core, never an unsigned agent report. The PostgreSQL transaction uses
// independently pinned signer/store/boot and preserves no-payload admission.
func (s *server) confirmTechnicalInstall(ctx context.Context,
	request *wrapperspb.BytesValue,
) (*emptypb.Empty, error) {
	bindings, err := s.authorize(ctx)
	if err != nil {
		return nil, err
	}
	if s.db == nil || request == nil || len(request.Value) == 0 ||
		len(request.Value) > 4096 || validateUniqueControlJobJSON(request.Value) != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid technical install proof")
	}
	var proof corepolicy.InstallReceipt
	decoder := json.NewDecoder(bytes.NewReader(request.Value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&proof); err != nil {
		return nil, status.Error(codes.InvalidArgument, "malformed installed evidence")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return nil, status.Error(codes.InvalidArgument, "trailing installed evidence")
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
		return nil, status.Error(codes.PermissionDenied, "foreign or superseded installed receipt")
	}
	err = journal.ConfirmTechnicalInstalled(ctx, s.db, proof)
	switch {
	case errors.Is(err, corepolicy.ErrInstallProof):
		return nil, status.Error(codes.PermissionDenied, "invalid pinned core signature or boot")
	case errors.Is(err, journal.ErrProfileAuthority),
		errors.Is(err, journal.ErrProfileConflict):
		return nil, status.Error(codes.FailedPrecondition, "technical install state not eligible for confirmation")
	case err != nil:
		return nil, status.Error(codes.Unavailable, "technical install confirmation unavailable")
	}
	return &emptypb.Empty{}, nil
}
