package policytransport

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"

	"github.com/ElXnet/ElX-control/internal/elxcontrol/corepolicy"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type TechnicalInstallProver interface {
	TechnicalInstaller
	ReadTechnicalInstalledProof(context.Context, []byte) (corepolicy.InstallReceipt, error)
}

// ApplyTechnicalInstall pulls only an authoritative Control-signed v2 INSTALL.
// It cannot synthesize a receipt: the real core signs a live installed witness,
// then the Control backend independently checks it against its PostgreSQL
// pinned core key/store/boot before advancing APPLIED.
// An uncertain ACK is retried under the same operation ID, never released.
func ApplyTechnicalInstall(ctx context.Context, conn grpc.ClientConnInterface,
	core TechnicalInstallProver, bindings []Binding, controlKey ed25519.PublicKey,
) error {
	if conn == nil || core == nil || len(controlKey) != ed25519.PublicKeySize ||
		ValidateBindings(bindings) != nil {
		return status.Error(codes.FailedPrecondition, "technical install agent lacks trusted bindings")
	}
	var next wrapperspb.BytesValue
	if err := conn.Invoke(ctx, "/"+serviceName+"/TechnicalInstallNext",
		&emptypb.Empty{}, &next); err != nil {
		return err
	}
	raw := next.Value
	if len(raw) == 0 || len(raw) > 4096 {
		return status.Error(codes.InvalidArgument, "invalid signed technical INSTALL delivery")
	}
	installed, err := VerifyAndInstallTechnicalProfile(ctx, raw, core, bindings, controlKey)
	if err != nil {
		return err
	}
	proof, err := core.ReadTechnicalInstalledProof(ctx, raw)
	if err != nil {
		return err
	}
	// Local validation minimizes accidental misdelivery and corrupted agent
	// traffic; only the Control-side database confirmation is authoritative.
	var job TechnicalProfileJob
	if err := validateUniqueControlJobJSON(raw); err != nil ||
		json.Unmarshal(raw, &job) != nil ||
		proof.OperationID != job.Grant.OperationID ||
		proof.ProfileID.String() != installed.ProfileID ||
		proof.NodeID != job.Grant.NodeID || proof.ResourceID != job.Grant.ResourceID ||
		proof.ExecutorID != job.Grant.ExecutorID ||
		proof.AuthorityGeneration != job.Grant.AuthorityGeneration ||
		proof.PolicyRevision != job.Grant.PolicyRevision {
		return status.Error(codes.FailedPrecondition, "core installed evidence mismatched signed Control grant")
	}
	var nodeSigner ed25519.PublicKey
	for _, b := range bindings {
		if b.Target.NodeID == proof.NodeID.String() &&
			b.Target.ResourceID == proof.ResourceID.String() &&
			b.ExecutorID == proof.ExecutorID.String() {
			nodeSigner = b.PublicKey
			break
		}
	}
	if len(nodeSigner) != ed25519.PublicKeySize ||
		!ed25519.Verify(nodeSigner, proof.Transcript(), proof.Signature) {
		return status.Error(codes.PermissionDenied, "core installed receipt signature differs from pinned node identity")
	}
	payload, err := json.Marshal(proof)
	if err != nil || len(payload) > 4096 {
		return errors.New("could not serialize bounded installed proof")
	}
	return conn.Invoke(ctx, "/"+serviceName+"/TechnicalInstallConfirm",
		wrapperspb.Bytes(payload), &emptypb.Empty{})
}
