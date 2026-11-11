package journal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"time"

	"github.com/ElXnet/ElX-control/internal/elxcontrol/corepolicy"
	"github.com/google/uuid"
)

// RetireReservation is authored by trusted Control, not a VPN node.
// Revocation is permitted even after a purchase expires, but never from
// another node, executor, subscription or superseded authority generation.
type RetireReservation struct {
	Grant              corepolicy.ProfileGrantIntent
	EntitlementID      string
	PinnedSubscription string
}

func validRetireReservation(r RetireReservation, now time.Time) bool {
	g := r.Grant
	ent, err := uuid.Parse(r.EntitlementID)
	return err == nil && ent != uuid.Nil && ent.String() == r.EntitlementID &&
		g.Version == 2 && g.Action == "retire" &&
		g.OperationID != uuid.Nil && g.NodeID != uuid.Nil && g.ResourceID != uuid.Nil &&
		g.ExecutorID != uuid.Nil && g.ProfileID != uuid.Nil &&
		g.ProfileGeneration == 2 && g.AuthorityGeneration > 0 &&
		g.PolicyRevision > 0 && g.SubscriptionID == r.PinnedSubscription &&
		technicalLabel.MatchString(g.SubscriptionID) && technicalLabel.MatchString(g.Email) &&
		technicalTag.MatchString(g.InboundTag) &&
		(g.Flow == "" || g.Flow == "xtls-rprx-vision") &&
		g.NotBefore <= now.Unix()+5 && g.NotAfter > now.Unix() &&
		g.NotAfter > g.NotBefore && g.NotAfter-g.NotBefore <= 60
}

// QueueTechnicalRetire stores a non-admitting and non-releasing RETIRE intent
// under the exact core witness and profile row lock. A pending INSTALL or a
// competing rate operation must first be reconciled, not speculatively undone.
func QueueTechnicalRetire(ctx context.Context, db *sql.DB,
	r RetireReservation) (ProfileReservationState, error) {
	var out ProfileReservationState
	if db == nil || !validRetireReservation(r, time.Now().UTC()) {
		return out, ErrInvalid
	}
	g := r.Grant
	out.OperationID, out.ProfileID = g.OperationID, g.ProfileID
	out.Digest = sha256.Sum256(g.Transcript())
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil { return out, err }
	defer tx.Rollback()
	var state string
	var installedFlow string
	err = tx.QueryRowContext(ctx, `SELECT p.state,
	    COALESCE((SELECT flow FROM elx_technical_profile_operations
	      WHERE profile_id=p.profile_id AND action='install' LIMIT 1),'')
	    FROM elx_technical_profiles p
	    JOIN elx_rate_grants g ON g.node_id=p.node_id AND g.resource_id=p.resource_id
	    JOIN elx_core_store_witnesses w ON w.node_id=p.node_id AND w.resource_id=p.resource_id
	    JOIN elx_operation_targets t ON t.node_id=p.node_id AND t.resource_id=p.resource_id
	    WHERE p.profile_id=$1 AND p.node_id=$2 AND p.resource_id=$3 AND p.executor_id=$4
	      AND NOT EXISTS (SELECT 1 FROM elx_technical_node_quarantines q WHERE q.node_id=p.node_id)
	      AND p.entitlement_id=$5 AND p.subscription_id=$6 AND p.email=$7
	      AND p.inbound_tag=$8 AND p.profile_generation+1=$9
	      AND p.authority_generation=$10 AND p.policy_revision=$11
	      AND g.entitlement_id=p.entitlement_id AND g.epoch=$10
	      AND w.executor_id=$4 AND w.authority_generation=$10 AND w.core_revision=$11
	      AND t.revision+1=$11
	      AND NOT EXISTS (SELECT 1 FROM elx_operations rate
	        WHERE rate.node_id=p.node_id AND rate.resource_id=p.resource_id
	          AND rate.applied_at IS NULL)
	      AND NOT EXISTS (SELECT 1 FROM elx_technical_profile_operations install
	        WHERE install.profile_id=p.profile_id AND install.action='install'
	          AND install.state='INTENT')
	    FOR UPDATE OF p,g,w,t`,
		g.ProfileID, g.NodeID, g.ResourceID, g.ExecutorID, r.EntitlementID,
		g.SubscriptionID, g.Email, g.InboundTag, g.ProfileGeneration,
		g.AuthorityGeneration, g.PolicyRevision).Scan(&state, &installedFlow)
	if errors.Is(err, sql.ErrNoRows) { return out, ErrProfileAuthority }
	if err != nil { return out, err }
	if g.Flow != installedFlow { return out, ErrProfileConflict }

	var existingProfile, existingAction, existingState, existingFlow string
	var existingHash []byte
	err = tx.QueryRowContext(ctx, `SELECT profile_id::text,action,state,flow,payload_sha256
	    FROM elx_technical_profile_operations WHERE operation_id=$1 FOR UPDATE`,
		g.OperationID).Scan(&existingProfile, &existingAction, &existingState, &existingFlow, &existingHash)
	if err == nil {
		if existingProfile != g.ProfileID.String() || existingAction != "retire" ||
			existingFlow != g.Flow || !bytes.Equal(existingHash, out.Digest[:]) {
			return out, ErrProfileConflict
		}
		out.State, out.AlreadyQueued = existingState, true
		return out, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) { return out, err }
	if state != "prepared" && state != "installed" {
		return out, ErrProfileConflict
	}
	var already bool
	if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM elx_technical_profile_operations
	    WHERE profile_id=$1 AND action='retire')`, g.ProfileID).Scan(&already); err != nil {
		return out, err
	}
	if already { return out, ErrProfileConflict }
	_, err = tx.ExecContext(ctx, `INSERT INTO elx_technical_profile_operations
	    (operation_id,profile_id,action,payload_sha256,profile_generation,
	     authority_generation,policy_revision,not_before,not_after,state,flow)
	    VALUES($1,$2,'retire',$3,$4,$5,$6,$7,$8,'INTENT',$9)`,
		g.OperationID, g.ProfileID, out.Digest[:], g.ProfileGeneration,
		g.AuthorityGeneration, g.PolicyRevision, g.NotBefore, g.NotAfter, g.Flow)
	if err != nil { return out, err }
	if err := tx.Commit(); err != nil { return out, err }
	out.State = "INTENT"
	return out, nil
}

// NextTechnicalRetire reconstructs only an unexpired, exact signed intent.
// The returned canonical bytes must be signed with Control's private key.
func NextTechnicalRetire(ctx context.Context, db *sql.DB,
	target Target, executorID, subscriptionID string) (corepolicy.ProfileGrantIntent, error) {
	if db == nil || !uuidValid(target.NodeID) || !uuidValid(target.ResourceID) ||
		!uuidValid(executorID) || !technicalLabel.MatchString(subscriptionID) {
		return corepolicy.ProfileGrantIntent{}, ErrInvalid
	}
	var op, profile, email, tag, flow string
	var generation, authority, revision, notBefore, notAfter int64
	var digest []byte
	err := db.QueryRowContext(ctx, `SELECT o.operation_id::text,p.profile_id::text,
	    p.email,p.inbound_tag,o.flow,o.profile_generation,o.authority_generation,
	    o.policy_revision,o.not_before,o.not_after,o.payload_sha256
	    FROM elx_technical_profile_operations o
	    JOIN elx_technical_profiles p ON p.profile_id=o.profile_id
	    JOIN elx_rate_grants g ON g.node_id=p.node_id AND g.resource_id=p.resource_id
	    JOIN elx_core_store_witnesses w ON w.node_id=p.node_id AND w.resource_id=p.resource_id
	    JOIN elx_operation_targets t ON t.node_id=p.node_id AND t.resource_id=p.resource_id
	    WHERE p.node_id=$1 AND p.resource_id=$2 AND p.executor_id=$3
	      AND NOT EXISTS (SELECT 1 FROM elx_technical_node_quarantines q WHERE q.node_id=p.node_id)
	      AND p.subscription_id=$4 AND p.state IN ('prepared','installed')
	      AND o.action='retire' AND o.state='INTENT'
	      AND o.profile_generation=p.profile_generation+1
	      AND o.authority_generation=p.authority_generation
	      AND o.policy_revision=p.policy_revision
	      AND g.entitlement_id=p.entitlement_id AND g.epoch=p.authority_generation
	      AND w.executor_id=p.executor_id AND w.authority_generation=p.authority_generation
	      AND w.core_revision=p.policy_revision AND t.revision+1=p.policy_revision
	      AND o.not_before<=EXTRACT(EPOCH FROM clock_timestamp())+5
	      AND o.not_after>EXTRACT(EPOCH FROM clock_timestamp())
	      AND NOT EXISTS (SELECT 1 FROM elx_operations rate
	        WHERE rate.node_id=p.node_id AND rate.resource_id=p.resource_id
	          AND rate.applied_at IS NULL)
	      AND NOT EXISTS (SELECT 1 FROM elx_technical_profile_operations install
	        WHERE install.profile_id=p.profile_id AND install.action='install'
	          AND install.state='INTENT')
	    ORDER BY o.created_at,o.operation_id LIMIT 1`,
		target.NodeID, target.ResourceID, executorID, subscriptionID).
		Scan(&op, &profile, &email, &tag, &flow, &generation,
			&authority, &revision, &notBefore, &notAfter, &digest)
	if err != nil { return corepolicy.ProfileGrantIntent{}, err }
	grant := corepolicy.ProfileGrantIntent{
		Version: 2, Action: "retire", OperationID: uuid.MustParse(op),
		ProfileID: uuid.MustParse(profile), NodeID: uuid.MustParse(target.NodeID),
		ExecutorID: uuid.MustParse(executorID), ResourceID: uuid.MustParse(target.ResourceID),
		SubscriptionID: subscriptionID, Email: email, InboundTag: tag, Flow: flow,
		ProfileGeneration: uint64(generation), AuthorityGeneration: uint64(authority),
		PolicyRevision: uint64(revision), NotBefore: notBefore, NotAfter: notAfter,
	}
	sum := sha256.Sum256(grant.Transcript())
	if generation != 2 || authority <= 0 || revision <= 0 ||
		(flow != "" && flow != "xtls-rprx-vision") || !bytes.Equal(digest, sum[:]) {
		return corepolicy.ProfileGrantIntent{}, ErrProfileAuthority
	}
	return grant, nil
}
