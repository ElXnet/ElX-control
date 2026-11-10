package policytransport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/ElXnet/ElX-control/internal/elxcontrol/corepolicy"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type TechnicalPreparer interface {
	PrepareTechnicalProfile(context.Context, []byte) (corepolicy.TechnicalPrepared, error)
	ReadbackTechnicalProfile(context.Context, string) (corepolicy.TechnicalPrepared, error)
}

// ApplyTechnicalPreparation carries only the Control-signed bounded PREPARE
// intent. It never calls AddUser, acknowledges APPLIED, releases a paid slot,
// or grants device admission. The core enforces its independent pinned key
// and SO_PEERCRED agent identity before persisting anything.
func ApplyTechnicalPreparation(ctx context.Context, conn grpc.ClientConnInterface,
	core TechnicalPreparer, bindings []Binding, pinnedControlKey ed25519.PublicKey) error {
	if conn == nil || core == nil || len(pinnedControlKey) != ed25519.PublicKeySize ||
		ValidateBindings(bindings) != nil {
		return status.Error(codes.FailedPrecondition, "technical preparation lacks trusted local bindings")
	}
	var response wrapperspb.BytesValue
	if err := conn.Invoke(ctx, "/"+serviceName+"/TechnicalProfileNext",
		&emptypb.Empty{}, &response); err != nil {
		return err
	}
	if len(response.Value) == 0 || len(response.Value) > 4096 {
		return status.Error(codes.InvalidArgument, "invalid Control technical job size")
	}
	var job TechnicalProfileJob
	decoder := json.NewDecoder(bytes.NewReader(response.Value))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&job); err != nil || decoder.More() {
		return status.Error(codes.InvalidArgument, "invalid signed technical profile envelope")
	}
	grant := job.Grant
	if grant.Version != 1 || grant.Action != "prepare" ||
		grant.ProfileGeneration != 1 ||
		grant.NotBefore > time.Now().Unix()+5 ||
		grant.NotAfter <= time.Now().Unix() ||
		grant.NotAfter-grant.NotBefore > 60 ||
		len(job.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(pinnedControlKey, grant.Transcript(), job.Signature) {
		return status.Error(codes.PermissionDenied, "invalid signed technical profile authority")
	}
	assigned := false
	for _, b := range bindings {
		if b.Target.NodeID == grant.NodeID.String() &&
			b.Target.ResourceID == grant.ResourceID.String() &&
			b.ExecutorID == grant.ExecutorID.String() &&
			b.Epoch > 0 && uint64(b.Epoch) == grant.AuthorityGeneration &&
			b.Subscription == grant.SubscriptionID {
			assigned = true
			break
		}
	}
	if !assigned {
		return status.Error(codes.PermissionDenied, "technical profile belongs to foreign executor or grant")
	}
	prepared, err := core.PrepareTechnicalProfile(ctx, response.Value)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(grant.Transcript())
	if prepared.Phase != "PREPARED" ||
		prepared.ProfileID != grant.ProfileID.String() ||
		prepared.OperationID != grant.OperationID.String() ||
		prepared.NodeID != grant.NodeID.String() ||
		prepared.ResourceID != grant.ResourceID.String() ||
		prepared.ExecutorID != grant.ExecutorID.String() ||
		prepared.SubscriptionID != grant.SubscriptionID ||
		prepared.Email != grant.Email ||
		prepared.InboundTag != grant.InboundTag ||
		prepared.ProfileGeneration != grant.ProfileGeneration ||
		prepared.AuthorityGeneration != grant.AuthorityGeneration ||
		prepared.PolicyRevision != grant.PolicyRevision ||
		prepared.TranscriptSHA256 != hex.EncodeToString(digest[:]) {
		return status.Error(codes.FailedPrecondition, "core prepared readback differs from signed Control intent")
	}
	readback, err := core.ReadbackTechnicalProfile(ctx, grant.ProfileID.String())
	if err != nil {
		return err
	}
	if readback != prepared {
		return status.Error(codes.FailedPrecondition, "core durable technical profile readback is inconsistent")
	}
	// Control keeps this operation at INTENT until a separate future
	// signature proves actual VLESS registration and safe readback.
	return nil
}

var ErrTechnicalPreparationNotInstalled = errors.New("technical profile prepared; live installation not yet implemented")
