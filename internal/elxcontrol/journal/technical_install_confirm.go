package journal

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"errors"

	"github.com/ElXnet/ElX-control/internal/elxcontrol/corepolicy"
	"github.com/google/uuid"
)

// ConfirmTechnicalInstalled atomically verifies a core-signed live VLESS
// receipt against independently pinned Control store/boot/core-key witnesses.
// No node-provided key, store ID, operation state or unsigned status is trusted.
// APPLIED means technical user installation only, NOT device/owner admission.
func ConfirmTechnicalInstalled(ctx context.Context, db *sql.DB,
	proof corepolicy.InstallReceipt) error {
	if db == nil || proof.Version != 1 || proof.NodeID == uuid.Nil ||
		proof.ResourceID == uuid.Nil || proof.ExecutorID == uuid.Nil ||
		proof.OperationID == uuid.Nil || proof.ProfileID == uuid.Nil ||
		proof.CoreIncarnation == uuid.Nil || proof.StoreID == uuid.Nil ||
		len(proof.Signature) != ed25519.SignatureSize {
		return corepolicy.ErrInstallProof
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var profileID, nodeID, resourceID, executorID, subscriptionID, email, inboundTag string
	var state, phase, flow string
	var gen, epoch, revision, notBefore, notAfter int64
	var digest, publicKey []byte
	var storeID, incarnation string
	err = tx.QueryRowContext(ctx, `SELECT
	    p.profile_id::text,p.node_id::text,p.resource_id::text,p.executor_id::text,
	    p.subscription_id,p.email,p.inbound_tag,p.profile_generation,
	    p.authority_generation,p.policy_revision,
	    p.state,o.state,o.flow,o.not_before,o.not_after,o.payload_sha256,
	    w.store_id::text,COALESCE(w.core_incarnation::text,''),c.public_key
	    FROM elx_technical_profile_operations o
	    JOIN elx_technical_profiles p ON p.profile_id=o.profile_id
	    JOIN elx_core_store_witnesses w ON w.node_id=p.node_id AND w.resource_id=p.resource_id
	    JOIN elx_core_identities c ON c.node_id=p.node_id AND c.incarnation=w.core_incarnation
	    JOIN elx_rate_grants g ON g.node_id=p.node_id AND g.resource_id=p.resource_id
	      AND g.entitlement_id=p.entitlement_id
	    JOIN elx_entitlements e ON e.id=p.entitlement_id
	    JOIN elx_operation_targets t ON t.node_id=p.node_id AND t.resource_id=p.resource_id
	    WHERE o.operation_id=$1 AND o.profile_id=$2 AND o.action='install'
	      AND p.node_id=$3 AND p.resource_id=$4 AND p.executor_id=$5
	      AND w.executor_id=p.executor_id AND NOT c.revoked
	      AND g.epoch=p.authority_generation AND w.authority_generation=p.authority_generation
	      AND w.core_revision=p.policy_revision AND t.revision+1=p.policy_revision
	      AND g.committed_up>0 AND g.committed_down>0
	      AND e.enabled AND e.valid_until>clock_timestamp()
	      AND NOT EXISTS (SELECT 1 FROM elx_operations rate
	          WHERE rate.node_id=p.node_id AND rate.resource_id=p.resource_id
	            AND rate.applied_at IS NULL)
	    FOR UPDATE OF o,p,w,g,t,c,e`,
		proof.OperationID, proof.ProfileID, proof.NodeID, proof.ResourceID,
		proof.ExecutorID).Scan(
			&profileID, &nodeID, &resourceID, &executorID, &subscriptionID,
			&email, &inboundTag, &gen, &epoch, &revision,
			&phase, &state, &flow, &notBefore, &notAfter, &digest,
			&storeID, &incarnation, &publicKey)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrProfileAuthority
	}
	if err != nil {
		return err
	}
	if gen != 1 || epoch <= 0 || revision <= 0 || phase == "retired" ||
		(state != "INTENT" && state != "APPLIED") {
		return ErrProfileAuthority
	}
	grant := corepolicy.ProfileGrantIntent{
		Version: 2, Action: "install",
		OperationID: proof.OperationID,
		ProfileID: uuid.MustParse(profileID),
		NodeID: uuid.MustParse(nodeID), ExecutorID: uuid.MustParse(executorID),
		ResourceID: uuid.MustParse(resourceID),
		SubscriptionID: subscriptionID, Email: email, InboundTag: inboundTag,
		Flow: flow, ProfileGeneration: uint64(gen),
		AuthorityGeneration: uint64(epoch), PolicyRevision: uint64(revision),
		NotBefore: notBefore, NotAfter: notAfter,
	}
	hash := sha256.Sum256(grant.Transcript())
	if !bytes.Equal(digest, hash[:]) {
		return ErrProfileAuthority
	}
	pinnedStore, errStore := uuid.Parse(storeID)
	pinnedBoot, errBoot := uuid.Parse(incarnation)
	if errStore != nil || errBoot != nil {
		return ErrProfileAuthority
	}
	if err := corepolicy.VerifyInstallReceipt(proof, grant,
		ed25519.PublicKey(publicKey), pinnedStore, pinnedBoot); err != nil {
		return err
	}
	if state == "APPLIED" {
		if phase != "installed" {
			return ErrProfileConflict
		}
		return tx.Commit()
	}
	if phase != "prepared" {
		return ErrProfileConflict
	}
	if _, err := tx.ExecContext(ctx, `UPDATE elx_technical_profile_operations
	    SET state='APPLIED',applied_at=clock_timestamp()
	    WHERE operation_id=$1 AND state='INTENT'`, proof.OperationID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE elx_technical_profiles
	    SET state='installed',updated_at=clock_timestamp()
	    WHERE profile_id=$1 AND state='prepared'`, proof.ProfileID); err != nil {
		return err
	}
	return tx.Commit()
}
