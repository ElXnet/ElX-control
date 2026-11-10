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
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TechnicalInstaller invokes only the protected ElXray install/readback RPCs.
// Control's central APPLIED confirmation is intentionally NOT part of this
// interface: it requires separately core-signed live-install evidence.
type TechnicalInstaller interface {
	InstallTechnicalProfile(context.Context, []byte) (corepolicy.TechnicalPrepared, error)
	ReadbackTechnicalProfile(context.Context, string) (corepolicy.TechnicalPrepared, error)
}

// VerifyAndInstallTechnicalProfile accepts exactly one short-lived Control-
// signed v2 INSTALL command; a v1 PREPARE can never be promoted into AddUser.
// The local readback is useful for reconciliation but never suffices to ACK
// centrally committed subscription rights or release a concurrent slot.
func VerifyAndInstallTechnicalProfile(ctx context.Context, raw []byte,
	core TechnicalInstaller, bindings []Binding, pinnedControlKey ed25519.PublicKey,
) (corepolicy.TechnicalPrepared, error) {
	invalid := corepolicy.TechnicalPrepared{}
	if core == nil || len(raw) == 0 || len(raw) > 4096 ||
		len(pinnedControlKey) != ed25519.PublicKeySize || ValidateBindings(bindings) != nil {
		return invalid, status.Error(codes.FailedPrecondition, "technical install requires pinned node authority")
	}
	if err := validateUniqueControlJobJSON(raw); err != nil {
		return invalid, status.Error(codes.InvalidArgument, "ambiguous signed install job")
	}
	var job TechnicalProfileJob
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&job); err != nil {
		return invalid, status.Error(codes.InvalidArgument, "invalid signed install job")
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return invalid, status.Error(codes.InvalidArgument, "trailing install job data")
	}
	g := job.Grant
	now := time.Now().UTC().Unix()
	if g.Version != 2 || g.Action != "install" || g.ProfileGeneration != 1 ||
		(g.Flow != "" && g.Flow != "xtls-rprx-vision") ||
		g.NotBefore > now+5 || g.NotAfter <= now ||
		g.NotAfter <= g.NotBefore || g.NotAfter-g.NotBefore > 60 ||
		len(job.Signature) != ed25519.SignatureSize ||
		!ed25519.Verify(pinnedControlKey, g.Transcript(), job.Signature) {
		return invalid, status.Error(codes.PermissionDenied, "unsigned, stale or downgraded VLESS INSTALL")
	}
	matches := false
	for _, b := range bindings {
		if b.Target.NodeID == g.NodeID.String() && b.Target.ResourceID == g.ResourceID.String() &&
			b.ExecutorID == g.ExecutorID.String() && b.Subscription == g.SubscriptionID &&
			b.Epoch > 0 && uint64(b.Epoch) == g.AuthorityGeneration {
			matches = true
			break
		}
	}
	if !matches {
		return invalid, status.Error(codes.PermissionDenied, "VLESS installation belongs to another executor")
	}
	installed, err := core.InstallTechnicalProfile(ctx, raw)
	if err != nil {
		return invalid, err
	}
	hash := sha256.Sum256(g.Transcript())
	if installed.Phase != "INSTALLED" || installed.ProfileID != g.ProfileID.String() ||
		installed.NodeID != g.NodeID.String() || installed.ResourceID != g.ResourceID.String() ||
		installed.ExecutorID != g.ExecutorID.String() || installed.SubscriptionID != g.SubscriptionID ||
		installed.Email != g.Email || installed.InboundTag != g.InboundTag ||
		installed.ProfileGeneration != g.ProfileGeneration ||
		installed.AuthorityGeneration != g.AuthorityGeneration ||
		installed.PolicyRevision != g.PolicyRevision ||
		installed.InstallOperationID != g.OperationID.String() ||
		installed.InstallTranscriptSHA256 != hex.EncodeToString(hash[:]) ||
		installed.Flow != g.Flow {
		return invalid, status.Error(codes.FailedPrecondition, "VLESS installed readback differs from signed intent")
	}
	again, err := core.ReadbackTechnicalProfile(ctx, g.ProfileID.String())
	if err != nil {
		return invalid, err
	}
	if again != installed {
		return invalid, status.Error(codes.FailedPrecondition, "inconsistent live VLESS install readback")
	}
	return installed, nil
}
