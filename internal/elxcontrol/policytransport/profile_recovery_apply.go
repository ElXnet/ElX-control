package policytransport

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"

	"github.com/ElXnet/ElX-control/internal/elxcontrol/corepolicy"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type TechnicalRecoveryCore interface {
	ReadRecoveredTechnicalInstalledProof(context.Context, string, string) (corepolicy.InstallReceipt, error)
	ReadRecoveredTechnicalRetiredProof(context.Context, string, string) (corepolicy.RetireReceipt, error)
}

// ApplyTechnicalRecovery is deliberately read-only at the ElXray boundary.
// Expired INSTALL/RETIRE instructions are NEVER replayed. Control may mark
// an old intent APPLIED only after authenticating the core's new signature
// against its independent PostgreSQL core identity and store/boot witness.
func ApplyTechnicalRecovery(ctx context.Context, conn grpc.ClientConnInterface,
	core TechnicalRecoveryCore, bindings []Binding,
) error {
	if conn == nil || core == nil || ValidateBindings(bindings) != nil {
		return status.Error(codes.FailedPrecondition, "technical recovery requires trusted bindings")
	}
	var message wrapperspb.BytesValue
	if err := conn.Invoke(ctx, "/"+serviceName+"/TechnicalRecoveryNext",
		&emptypb.Empty{}, &message); err != nil { return err }
	if len(message.Value) == 0 || len(message.Value) > 4096 ||
		validateUniqueControlJobJSON(message.Value) != nil {
		return status.Error(codes.InvalidArgument,"invalid bounded technical recovery assignments")
	}
	var jobs []TechnicalRecoveryJob
	if err := json.Unmarshal(message.Value, &jobs); err != nil ||
		len(jobs) == 0 || len(jobs) > 8 {
		return status.Error(codes.InvalidArgument,"invalid technical recovery window")
	}
	confirmed := 0
	for _, job := range jobs {
		id, idErr := uuid.Parse(job.ProfileID)
		op, opErr := uuid.Parse(job.OperationID)
		if idErr != nil || opErr != nil || id == uuid.Nil || op == uuid.Nil ||
			id.String() != job.ProfileID || op.String() != job.OperationID ||
			(job.Action != "install" && job.Action != "retire") {
			return status.Error(codes.PermissionDenied,"invalid technical recovery identity")
		}
		var signer ed25519.PublicKey
		for _, b := range bindings {
			if b.Target.NodeID == job.NodeID && b.Target.ResourceID == job.ResourceID &&
				b.ExecutorID == job.ExecutorID && b.Subscription == job.SubscriptionID &&
				b.Epoch > 0 && uint64(b.Epoch) == job.AuthorityGeneration {
				signer = b.PublicKey
				break
			}
		}
		if len(signer) != ed25519.PublicKeySize {
			return status.Error(codes.PermissionDenied,"foreign or superseded technical recovery request")
		}
		var proofBytes []byte
		var method string
		switch job.Action {
		case "install":
			proof, err := core.ReadRecoveredTechnicalInstalledProof(ctx, job.ProfileID, job.OperationID)
			if err != nil {
				if status.Code(err) == codes.FailedPrecondition || status.Code(err) == codes.NotFound {
					continue // not proven; never send a receipt
				}
				return err
			}
			if proof.Version != 1 || proof.OperationID != op || proof.ProfileID != id ||
				proof.NodeID.String() != job.NodeID || proof.ResourceID.String() != job.ResourceID ||
				proof.ExecutorID.String() != job.ExecutorID ||
				proof.AuthorityGeneration != job.AuthorityGeneration ||
				!ed25519.Verify(signer, proof.Transcript(), proof.Signature) {
				return status.Error(codes.PermissionDenied,"untrusted recovered core INSTALL proof")
			}
			proofBytes,err=json.Marshal(proof)
			if err!=nil { return err }
			method="TechnicalInstallConfirm"
		case "retire":
			proof, err := core.ReadRecoveredTechnicalRetiredProof(ctx, job.ProfileID, job.OperationID)
			if err != nil {
				if status.Code(err) == codes.FailedPrecondition || status.Code(err) == codes.NotFound {
					continue // unknown data-plane mutation stays pending
				}
				return err
			}
			if proof.Version != 1 || proof.OperationID != op || proof.ProfileID != id ||
				proof.NodeID.String() != job.NodeID || proof.ResourceID.String() != job.ResourceID ||
				proof.ExecutorID.String() != job.ExecutorID ||
				proof.AuthorityGeneration != job.AuthorityGeneration ||
				proof.RetireGeneration != 2 ||
				!ed25519.Verify(signer, proof.Transcript(), proof.Signature) {
				return status.Error(codes.PermissionDenied,"untrusted recovered core RETIRE proof")
			}
			proofBytes,err=json.Marshal(proof)
			if err!=nil { return err }
			method="TechnicalRetireConfirm"
		}
		if len(proofBytes) == 0 || len(proofBytes) > 4096 {
			return errors.New("invalid bounded recovered core receipt")
		}
		if err := conn.Invoke(ctx, "/"+serviceName+"/"+method,
			wrapperspb.Bytes(proofBytes), &emptypb.Empty{}); err != nil {
			return err // no central proof, no status transition
		}
		confirmed++
	}
	if confirmed == 0 {
		return status.Error(codes.FailedPrecondition,"expired operations remain unproven; manual reconciliation required")
	}
	return nil
}
