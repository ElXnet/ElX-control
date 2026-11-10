package policytransport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/ElXnet/ElX-control/internal/elxcontrol/corepolicy"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type TechnicalRetireProver interface {
	RetireTechnicalProfile(context.Context, []byte) (corepolicy.TechnicalPrepared, error)
	ReadTechnicalRetiredProof(context.Context, []byte) (corepolicy.RetireReceipt, error)
	ReadbackTechnicalProfile(context.Context, string) (corepolicy.TechnicalPrepared, error)
}

// ApplyTechnicalRetire cannot release a device slot on a local readback.
// Only Control's independently pinned core/store witness may confirm APPLIED.
func ApplyTechnicalRetire(ctx context.Context, conn grpc.ClientConnInterface,
	core TechnicalRetireProver, bindings []Binding, controlKey ed25519.PublicKey,
) error {
	if conn == nil || core == nil || len(controlKey) != ed25519.PublicKeySize ||
		ValidateBindings(bindings) != nil {
		return status.Error(codes.FailedPrecondition, "technical RETIRE lacks trusted binding")
	}
	var next wrapperspb.BytesValue
	if err := conn.Invoke(ctx, "/"+serviceName+"/TechnicalRetireNext",
		&emptypb.Empty{}, &next); err != nil {
		return err
	}
	raw := next.Value
	if len(raw) == 0 || len(raw) > 4096 ||
		validateUniqueControlJobJSON(raw) != nil {
		return status.Error(codes.InvalidArgument, "invalid signed RETIRE delivery")
	}
	var job TechnicalProfileJob
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&job); err != nil {
		return status.Error(codes.InvalidArgument, "ambiguous signed RETIRE job")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return status.Error(codes.InvalidArgument, "trailing signed RETIRE job")
	}
	g := job.Grant
	now := time.Now().UTC().Unix()
	if g.Version != 2 || g.Action != "retire" || g.ProfileGeneration != 2 ||
		(g.Flow != "" && g.Flow != "xtls-rprx-vision") ||
		g.NotBefore > now+5 || g.NotAfter <= now ||
		g.NotAfter <= g.NotBefore || g.NotAfter-g.NotBefore > 60 ||
		len(job.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(controlKey, g.Transcript(), job.Signature) {
		return status.Error(codes.PermissionDenied, "untrusted signed VLESS RETIRE")
	}
	var signer ed25519.PublicKey
	for _, b := range bindings {
		if b.Target.NodeID == g.NodeID.String() &&
			b.Target.ResourceID == g.ResourceID.String() &&
			b.ExecutorID == g.ExecutorID.String() &&
			b.Subscription == g.SubscriptionID && b.Epoch > 0 &&
			uint64(b.Epoch) == g.AuthorityGeneration {
			signer = b.PublicKey
			break
		}
	}
	if len(signer) != ed25519.PublicKeySize {
		return status.Error(codes.PermissionDenied, "RETIRE belongs to foreign executor")
	}
	retired, err := core.RetireTechnicalProfile(ctx, raw)
	if err != nil { return err }
	digest := sha256.Sum256(g.Transcript())
	if retired.Phase != "RETIRED" ||
		retired.ProfileID != g.ProfileID.String() ||
		retired.RetireOperationID != g.OperationID.String() ||
		retired.RetireTranscriptSHA256 != hex.EncodeToString(digest[:]) ||
		retired.RetireGeneration != g.ProfileGeneration ||
		retired.NodeID != g.NodeID.String() ||
		retired.ExecutorID != g.ExecutorID.String() ||
		retired.ResourceID != g.ResourceID.String() ||
		retired.SubscriptionID != g.SubscriptionID ||
		retired.Email != g.Email || retired.InboundTag != g.InboundTag ||
		retired.Flow != g.Flow ||
		retired.AuthorityGeneration != g.AuthorityGeneration ||
		retired.PolicyRevision != g.PolicyRevision {
		return status.Error(codes.FailedPrecondition, "retire readback differs from signed intent")
	}
	again, err := core.ReadbackTechnicalProfile(ctx, g.ProfileID.String())
	if err != nil || again != retired {
		return status.Error(codes.FailedPrecondition, "inconsistent durable RETIRED readback")
	}
	proof, err := core.ReadTechnicalRetiredProof(ctx, raw)
	if err != nil { return err }
	if proof.OperationID != g.OperationID || proof.ProfileID != g.ProfileID ||
		proof.NodeID != g.NodeID || proof.ResourceID != g.ResourceID ||
		proof.ExecutorID != g.ExecutorID ||
		proof.RetireGeneration != g.ProfileGeneration ||
		proof.AuthorityGeneration != g.AuthorityGeneration ||
		proof.PolicyRevision != g.PolicyRevision ||
		proof.TranscriptSHA256 != hex.EncodeToString(digest[:]) ||
		!ed25519.Verify(signer, proof.Transcript(), proof.Signature) {
		return status.Error(codes.PermissionDenied, "untrusted core-signed RETIRED proof")
	}
	payload, err := json.Marshal(proof)
	if err != nil || len(payload) > 4096 {
		return errors.New("cannot encode bounded RETIRED evidence")
	}
	return conn.Invoke(ctx, "/"+serviceName+"/TechnicalRetireConfirm",
		wrapperspb.Bytes(payload), &emptypb.Empty{})
}
