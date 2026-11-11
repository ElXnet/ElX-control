package journal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"strings"

	"github.com/google/uuid"
)

// TechnicalNodeQuarantine is an administrative FENCE record for a physically
// isolated node with an interrupted technical mutation. It deliberately does
// not update the original INTENT or turn an unproven outcome into APPLIED.
// No purchased entitlement, rate grant, owner slot, or UUID is released.
type TechnicalNodeQuarantine struct {
	NodeID         string
	ResourceID     string
	ProfileID      string
	OperationID    string
	StoreID        string
	Phase          string
	EvidenceSHA256 string
	OperatorRef    string
	ConfirmedNode  string
}

func validTechnicalQuarantine(req TechnicalNodeQuarantine) ([]byte, error) {
	for _, raw := range []string{
		req.NodeID, req.ResourceID, req.ProfileID, req.OperationID, req.StoreID,
	} {
		id, err := uuid.Parse(raw)
		if err != nil || id == uuid.Nil || id.String() != raw {
			return nil, ErrInvalid
		}
	}
	if req.ConfirmedNode != req.NodeID ||
		(req.Phase != "INSTALLING" && req.Phase != "RETIRING") ||
		len(req.OperatorRef) < 3 || len(req.OperatorRef) > 128 ||
		strings.TrimSpace(req.OperatorRef) != req.OperatorRef ||
		strings.ContainsAny(req.OperatorRef, "\r\n\t") {
		return nil, ErrInvalid
	}
	evidence, err := hex.DecodeString(req.EvidenceSHA256)
	if err != nil || len(evidence) != sha256.Size ||
		hex.EncodeToString(evidence) != req.EvidenceSHA256 ||
		bytes.Equal(evidence, make([]byte, sha256.Size)) {
		return nil, ErrInvalid
	}
	return evidence, nil
}

// QuarantineTechnicalNode is called only by the privileged operator CLI,
// after external isolation of the entire node and an offline journal/anchor
// inspection. PostgreSQL validates the original Control INTENT and its
// independently provisioned store witness under row locks. Repeating the
// identical request is safe; attempting to replace an incident is forbidden.
//
// A stored quarantine prevents fresh Control-signed store witnesses and all
// further technical deliveries for this node. Existing expiring leases and
// physical isolation are independently required; SQL alone cannot cut off
// an already running, malicious or disconnected machine.
func QuarantineTechnicalNode(ctx context.Context, db *sql.DB, req TechnicalNodeQuarantine) error {
	if db == nil {
		return ErrInvalid
	}
	evidence, err := validTechnicalQuarantine(req)
	if err != nil {
		return err
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return err
	}
	defer tx.Rollback()

	var operationState, action, profileState, storeID string
	err = tx.QueryRowContext(ctx, `SELECT o.state,o.action,p.state,w.store_id::text
		FROM elx_technical_profiles p
		JOIN elx_technical_profile_operations o ON o.profile_id=p.profile_id
		JOIN elx_core_store_witnesses w ON
			w.node_id=p.node_id AND w.resource_id=p.resource_id
		WHERE p.node_id=$1 AND p.resource_id=$2
		  AND p.profile_id=$3 AND o.operation_id=$4
		FOR UPDATE OF o,p,w`,
		req.NodeID, req.ResourceID, req.ProfileID, req.OperationID).
		Scan(&operationState, &action, &profileState, &storeID)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrProfileAuthority
	}
	if err != nil {
		return err
	}
	if storeID != req.StoreID || operationState != "INTENT" {
		return ErrProfileAuthority
	}
	if (req.Phase == "INSTALLING" && (action != "install" || profileState != "prepared")) ||
		(req.Phase == "RETIRING" && (action != "retire" ||
			(profileState != "installed" && profileState != "prepared"))) {
		return ErrProfileConflict
	}

	_, err = tx.ExecContext(ctx, `INSERT INTO elx_technical_node_quarantines
		(node_id,resource_id,profile_id,operation_id,store_id,phase,evidence_sha256,operator_ref)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8)
		ON CONFLICT (node_id) DO NOTHING`,
		req.NodeID, req.ResourceID, req.ProfileID, req.OperationID,
		req.StoreID, req.Phase, evidence, req.OperatorRef)
	if err != nil {
		return err
	}
	var resource, profile, operation, store, phase, operator string
	var saved []byte
	if err := tx.QueryRowContext(ctx, `SELECT resource_id::text,profile_id::text,
		operation_id::text,store_id::text,phase,evidence_sha256,operator_ref
		FROM elx_technical_node_quarantines WHERE node_id=$1 FOR UPDATE`,
		req.NodeID).Scan(&resource, &profile, &operation, &store, &phase, &saved, &operator); err != nil {
		return err
	}
	if resource != req.ResourceID || profile != req.ProfileID ||
		operation != req.OperationID || store != req.StoreID ||
		phase != req.Phase || operator != req.OperatorRef ||
		!bytes.Equal(saved, evidence) {
		return ErrProfileConflict
	}
	return tx.Commit()
}

// TechnicalNodeQuarantined is the fail-closed gate for every Control lease
// witness and technical delivery. Database failure is an error, never false.
func TechnicalNodeQuarantined(ctx context.Context, db *sql.DB, nodeID string) (bool, error) {
	if db == nil || !uuidValid(nodeID) {
		return false, ErrInvalid
	}
	var found bool
	err := db.QueryRowContext(ctx, `SELECT EXISTS (
		SELECT 1 FROM elx_technical_node_quarantines WHERE node_id=$1)`, nodeID).Scan(&found)
	return found, err
}
