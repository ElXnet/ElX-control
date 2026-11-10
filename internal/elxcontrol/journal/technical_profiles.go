package journal

import (
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"time"

	"github.com/ElXnet/ElX-control/internal/elxcontrol/corepolicy"
	"github.com/google/uuid"
)

var ErrProfileConflict = errors.New("technical VLESS profile identity or operation conflict")
var ErrProfileAuthority = errors.New("technical profile grant is not bound to current purchased authority")

var technicalLabel = regexp.MustCompile(`^[A-Za-z0-9_.@+:-]{1,255}$`)
var technicalTag = regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)

// ProfileReservation is constructed by the trusted Control service from a
// current, mTLS-authenticated node assignment and privileged technical config.
// PinnedSubscription must come from trusted Control inventory, not request JSON.
type ProfileReservation struct {
	Grant              corepolicy.ProfileGrantIntent
	EntitlementID      string
	PinnedSubscription string
}

// ProfileReservationState is a durable, *non-admitting* Control intent. It is
// never proof that a VLESS user was installed or that any VPN payload is allowed.
type ProfileReservationState struct {
	OperationID uuid.UUID
	ProfileID   uuid.UUID
	State       string
	Digest      [sha256.Size]byte
	AlreadyQueued bool
}

func validTechnicalReservation(r ProfileReservation, now time.Time) bool {
	g := r.Grant
	if g.Version != 1 || g.Action != "prepare" ||
		g.NodeID == uuid.Nil || g.ResourceID == uuid.Nil ||
		g.ExecutorID == uuid.Nil || g.OperationID == uuid.Nil ||
		g.ProfileID == uuid.Nil || g.ProfileGeneration != 1 ||
		g.AuthorityGeneration == 0 || g.PolicyRevision == 0 ||
		g.NotAfter <= g.NotBefore || g.NotAfter-g.NotBefore > 60 ||
		g.NotAfter <= now.Unix() || g.NotBefore > now.Unix()+5 ||
		g.SubscriptionID != r.PinnedSubscription ||
		!technicalLabel.MatchString(g.SubscriptionID) ||
		!technicalLabel.MatchString(g.Email) ||
		!technicalTag.MatchString(g.InboundTag) ||
		len(g.Transcript()) == 0 {
		return false
	}
	entitlement, err := uuid.Parse(r.EntitlementID)
	return err == nil && entitlement != uuid.Nil && entitlement.String() == r.EntitlementID
}

// QueueTechnicalProfile persists a signed-grant *candidate*, after checking
// purchased capacity, authority generation, pinned executor and policy CAS.
// It creates no live VLESS user, has no network admission side effect, and
// does not release committed capacity. Two concurrent requests to the same
// target serialize on PostgreSQL row locks.
func QueueTechnicalProfile(ctx context.Context, db *sql.DB,
	r ProfileReservation) (ProfileReservationState, error) {
	var out ProfileReservationState
	if db == nil || !validTechnicalReservation(r, time.Now().UTC()) {
		return out, ErrInvalid
	}
	g := r.Grant
	out.OperationID, out.ProfileID = g.OperationID, g.ProfileID
	out.Digest = sha256.Sum256(g.Transcript())

	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return out, err
	}
	defer tx.Rollback()

	var epoch, revision, committedUp, committedDown int64
	var executor string
	err = tx.QueryRowContext(ctx, `SELECT g.epoch,t.revision+1,g.committed_up,
	    g.committed_down,w.executor_id::text
	    FROM elx_rate_grants g
	    JOIN elx_operation_targets t USING(node_id,resource_id)
	    JOIN elx_core_store_witnesses w USING(node_id,resource_id)
	    JOIN elx_entitlements e ON e.id=g.entitlement_id
	    WHERE g.node_id=$1 AND g.resource_id=$2 AND g.entitlement_id=$3
	    AND e.enabled=true AND e.valid_until>clock_timestamp()
	    FOR UPDATE OF g,t,w`,
		g.NodeID, g.ResourceID, r.EntitlementID).
		Scan(&epoch, &revision, &committedUp, &committedDown, &executor)
	if errors.Is(err, sql.ErrNoRows) {
		return out, ErrProfileAuthority
	}
	if err != nil {
		return out, err
	}
	if epoch <= 0 || revision <= 0 || committedUp <= 0 || committedDown <= 0 ||
		uint64(epoch) != g.AuthorityGeneration ||
		uint64(revision) != g.PolicyRevision ||
		executor != g.ExecutorID.String() {
		return out, ErrProfileAuthority
	}

	var storedProfile, state string
	var storedDigest []byte
	err = tx.QueryRowContext(ctx, `SELECT profile_id::text,state,payload_sha256
	    FROM elx_technical_profile_operations
	    WHERE operation_id=$1 FOR UPDATE`, g.OperationID).
		Scan(&storedProfile, &state, &storedDigest)
	if err == nil {
		if storedProfile != g.ProfileID.String() ||
			!bytes.Equal(storedDigest, out.Digest[:]) {
			return out, ErrProfileConflict
		}
		out.State = state
		out.AlreadyQueued = true
		return out, tx.Commit()
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return out, err
	}

	var existing bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(
	    SELECT 1 FROM elx_technical_profiles WHERE profile_id=$1
	    OR (node_id=$2 AND executor_id=$3 AND inbound_tag=$4
	    AND email=$5 AND state<>'retired'))`,
		g.ProfileID, g.NodeID, g.ExecutorID, g.InboundTag, g.Email).
		Scan(&existing)
	if err != nil {
		return out, err
	}
	if existing {
		return out, ErrProfileConflict
	}

	var transitioning bool
	err = tx.QueryRowContext(ctx, `SELECT EXISTS(
	    SELECT 1 FROM elx_operations
	    WHERE node_id=$1 AND resource_id=$2 AND applied_at IS NULL)`,
		g.NodeID, g.ResourceID).Scan(&transitioning)
	if err != nil {
		return out, err
	}
	if transitioning {
		return out, ErrUncertain
	}

	_, err = tx.ExecContext(ctx, `INSERT INTO elx_technical_profiles
	    (profile_id,node_id,resource_id,executor_id,entitlement_id,
	    subscription_id,email,inbound_tag,profile_generation,
	    authority_generation,policy_revision,state,operation_id,request_sha256)
	    VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,'prepared',$12,$13)`,
		g.ProfileID, g.NodeID, g.ResourceID, g.ExecutorID, r.EntitlementID,
		g.SubscriptionID, g.Email, g.InboundTag, g.ProfileGeneration,
		g.AuthorityGeneration, g.PolicyRevision, g.OperationID, out.Digest[:])
	if err != nil {
		return out, fmt.Errorf("reserve technical profile: %w", err)
	}

	_, err = tx.ExecContext(ctx, `INSERT INTO elx_technical_profile_operations
	    (operation_id,profile_id,action,payload_sha256,profile_generation,
	    authority_generation,policy_revision,not_before,not_after,state)
	    VALUES($1,$2,'prepare',$3,$4,$5,$6,$7,$8,'INTENT')`,
		g.OperationID, g.ProfileID, out.Digest[:], g.ProfileGeneration,
		g.AuthorityGeneration, g.PolicyRevision, g.NotBefore, g.NotAfter)
	if err != nil {
		return out, fmt.Errorf("record technical profile intent: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return out, err
	}
	out.State = "INTENT"
	return out, nil
}

// NextTechnicalProfile is a read-only, bounded, authoritative operation
// projection for one exact mTLS-authenticated node/resource/executor. This
// function NEVER signs data and never changes the operation to APPLIED.
//
// A revoked entitlement, stale core revision, pending rate move, switched
// executor/store generation, expired grant or inconsistent signed hash is
// omitted rather than converted into an unsafe job.
func NextTechnicalProfile(ctx context.Context, db *sql.DB,
	target Target, executorID, subscriptionID string) (corepolicy.ProfileGrantIntent, error) {
	if db == nil || !canonical(target.NodeID) || !canonical(target.ResourceID) ||
		!canonical(executorID) || !technicalLabel.MatchString(subscriptionID) {
		return corepolicy.ProfileGrantIntent{}, ErrInvalid
	}
	now := time.Now().UTC()
	var g corepolicy.ProfileGrantIntent
	var profile, operation string
	var digest []byte
	var generation, epoch, revision, notBefore, notAfter int64
	var email, inboundTag string
	err := db.QueryRowContext(ctx, `SELECT
	    p.operation_id::text,p.profile_id::text,p.email,p.inbound_tag,
	    p.profile_generation,p.authority_generation,p.policy_revision,
	    o.not_before,o.not_after,o.payload_sha256
	    FROM elx_technical_profiles p
	    JOIN elx_technical_profile_operations o ON o.operation_id=p.operation_id
	       AND o.profile_id=p.profile_id
	    JOIN elx_rate_grants rg ON rg.node_id=p.node_id AND rg.resource_id=p.resource_id
	    JOIN elx_operation_targets t ON t.node_id=p.node_id AND t.resource_id=p.resource_id
	    JOIN elx_core_store_witnesses w ON w.node_id=p.node_id AND w.resource_id=p.resource_id
	    JOIN elx_entitlements e ON e.id=p.entitlement_id
	    WHERE p.node_id=$1 AND p.resource_id=$2 AND p.executor_id=$3
	      AND p.subscription_id=$4 AND p.state='prepared'
	      AND o.state='INTENT' AND o.action='prepare'
	      AND o.profile_generation=p.profile_generation
	      AND o.authority_generation=p.authority_generation
	      AND o.policy_revision=p.policy_revision
	      AND rg.entitlement_id=p.entitlement_id
	      AND rg.epoch=p.authority_generation
	      AND rg.epoch=w.authority_generation
	      AND w.executor_id=p.executor_id AND w.core_revision=p.policy_revision
	      AND t.revision+1=p.policy_revision
	      AND rg.committed_up>0 AND rg.committed_down>0
	      AND e.enabled=true AND e.valid_until>clock_timestamp()
	      AND o.not_before<=EXTRACT(EPOCH FROM clock_timestamp())+5
	      AND o.not_after>EXTRACT(EPOCH FROM clock_timestamp())
	      AND NOT EXISTS(SELECT 1 FROM elx_operations rate
	         WHERE rate.node_id=p.node_id AND rate.resource_id=p.resource_id AND rate.applied_at IS NULL)
	    ORDER BY p.created_at,p.profile_id LIMIT 1`,
		target.NodeID, target.ResourceID, executorID, subscriptionID).
		Scan(&operation,&profile,&email,&inboundTag,
			&generation,&epoch,&revision,&notBefore,&notAfter,&digest)
	if err != nil {
		return corepolicy.ProfileGrantIntent{}, err
	}
	g = corepolicy.ProfileGrantIntent{
		Version: 1, Action: "prepare",
		OperationID: uuid.MustParse(operation),
		NodeID: uuid.MustParse(target.NodeID), ResourceID: uuid.MustParse(target.ResourceID),
		ExecutorID: uuid.MustParse(executorID), ProfileID: uuid.MustParse(profile),
		SubscriptionID: subscriptionID, Email: email, InboundTag: inboundTag,
		ProfileGeneration: uint64(generation), AuthorityGeneration: uint64(epoch),
		PolicyRevision: uint64(revision), NotBefore: notBefore, NotAfter: notAfter,
	}
	computed := sha256.Sum256(g.Transcript())
	if generation != 1 || epoch <= 0 || revision <= 0 ||
		!validTechnicalReservation(ProfileReservation{Grant: g,
			EntitlementID: "00000000-0000-4000-8000-000000000001",
			PinnedSubscription: subscriptionID}, now) ||
		!bytes.Equal(digest, computed[:]) {
		return corepolicy.ProfileGrantIntent{}, ErrProfileAuthority
	}
	return g, nil
}
