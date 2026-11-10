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

// ConfirmTechnicalRetired only accepts a cryptographically valid live-core
// attestation with a pinned store/boot and exact persisted RETIRE transcript.
// APPLIED updates the technical ledger but NEVER releases a device owner slot,
// session fence or rate-grant reservation.
func ConfirmTechnicalRetired(ctx context.Context, db *sql.DB, proof corepolicy.RetireReceipt) error {
	if db == nil || proof.Version != 1 || proof.OperationID == uuid.Nil ||
		proof.ProfileID == uuid.Nil || proof.NodeID == uuid.Nil ||
		proof.ResourceID == uuid.Nil || proof.ExecutorID == uuid.Nil ||
		proof.StoreID == uuid.Nil || proof.CoreIncarnation == uuid.Nil ||
		proof.RetireGeneration != 2 || len(proof.Signature) != ed25519.SignatureSize {
		return corepolicy.ErrRetireProof
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil { return err }
	defer tx.Rollback()
	var profileID, nodeID, resourceID, executorID string
	var subscription, email, tag, flow, state, phase, storeID, boot string
	var generation, authority, revision, notBefore, notAfter int64
	var digest, key []byte
	err = tx.QueryRowContext(ctx, `SELECT
	    p.profile_id::text,p.node_id::text,p.resource_id::text,p.executor_id::text,
	    p.subscription_id,p.email,p.inbound_tag,o.flow,o.state,p.state,
	    o.profile_generation,o.authority_generation,o.policy_revision,
	    o.not_before,o.not_after,o.payload_sha256,
	    w.store_id::text,COALESCE(w.core_incarnation::text,''),c.public_key
	    FROM elx_technical_profile_operations o
	    JOIN elx_technical_profiles p ON p.profile_id=o.profile_id
	    JOIN elx_core_store_witnesses w ON w.node_id=p.node_id AND w.resource_id=p.resource_id
	    JOIN elx_core_identities c ON c.node_id=p.node_id AND c.incarnation=w.core_incarnation
	    JOIN elx_rate_grants g ON g.node_id=p.node_id AND g.resource_id=p.resource_id
	      AND g.entitlement_id=p.entitlement_id
	    JOIN elx_operation_targets t ON t.node_id=p.node_id AND t.resource_id=p.resource_id
	    WHERE o.operation_id=$1 AND o.profile_id=$2 AND o.action='retire'
	      AND p.node_id=$3 AND p.resource_id=$4 AND p.executor_id=$5
	      AND o.profile_generation=p.profile_generation+1
	      AND o.authority_generation=p.authority_generation
	      AND o.policy_revision=p.policy_revision
	      AND g.epoch=p.authority_generation
	      AND w.executor_id=p.executor_id AND w.authority_generation=p.authority_generation
	      AND w.core_revision=p.policy_revision AND t.revision+1=p.policy_revision
	      AND NOT c.revoked
	      AND NOT EXISTS (SELECT 1 FROM elx_operations rate
	         WHERE rate.node_id=p.node_id AND rate.resource_id=p.resource_id AND rate.applied_at IS NULL)
	    FOR UPDATE OF o,p,w,c,g,t`,
		proof.OperationID, proof.ProfileID, proof.NodeID, proof.ResourceID,
		proof.ExecutorID).Scan(
			&profileID, &nodeID, &resourceID, &executorID,
			&subscription, &email, &tag, &flow, &state, &phase,
			&generation, &authority, &revision, &notBefore, &notAfter,
			&digest, &storeID, &boot, &key)
	if errors.Is(err, sql.ErrNoRows) { return ErrProfileAuthority }
	if err != nil { return err }
	if generation != 2 || authority <= 0 || revision <= 0 ||
		(state != "INTENT" && state != "APPLIED") {
		return ErrProfileAuthority
	}
	g := corepolicy.ProfileGrantIntent{
		Version: 2, Action: "retire", OperationID: proof.OperationID,
		ProfileID: uuid.MustParse(profileID), NodeID: uuid.MustParse(nodeID),
		ResourceID: uuid.MustParse(resourceID), ExecutorID: uuid.MustParse(executorID),
		SubscriptionID: subscription, Email: email, InboundTag: tag,
		Flow: flow, ProfileGeneration: uint64(generation),
		AuthorityGeneration: uint64(authority), PolicyRevision: uint64(revision),
		NotBefore: notBefore, NotAfter: notAfter,
	}
	hash := sha256.Sum256(g.Transcript())
	if !bytes.Equal(digest, hash[:]) { return ErrProfileAuthority }
	pinnedStore, e1 := uuid.Parse(storeID)
	pinnedBoot, e2 := uuid.Parse(boot)
	if e1 != nil || e2 != nil { return ErrProfileAuthority }
	if err := corepolicy.VerifyRetireReceipt(proof, g,
		ed25519.PublicKey(key), pinnedStore, pinnedBoot); err != nil {
		return err
	}
	if state == "APPLIED" {
		if phase != "retired" { return ErrProfileConflict }
		return tx.Commit()
	}
	if phase != "prepared" && phase != "installed" { return ErrProfileConflict }
	// A core-signed final technical outcome also proves that the exact
	// PREPARE existed in the durable core journal. Close its original
	// Control intent in the SAME transaction, not from an agent ACK.
	if _, err := tx.ExecContext(ctx, `UPDATE elx_technical_profile_operations
	    SET state='APPLIED',applied_at=clock_timestamp()
	    WHERE profile_id=$1 AND action='prepare' AND state='INTENT'
	      AND operation_id=(SELECT operation_id FROM elx_technical_profiles WHERE profile_id=$1)
	      AND payload_sha256=(SELECT request_sha256 FROM elx_technical_profiles WHERE profile_id=$1)`,
		proof.ProfileID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE elx_technical_profile_operations
	    SET state='APPLIED',applied_at=clock_timestamp()
	    WHERE operation_id=$1 AND state='INTENT'`, proof.OperationID); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `UPDATE elx_technical_profiles
	    SET state='retired',updated_at=clock_timestamp()
	    WHERE profile_id=$1 AND state IN ('prepared','installed')`, proof.ProfileID); err != nil {
		return err
	}
	return tx.Commit()
}
