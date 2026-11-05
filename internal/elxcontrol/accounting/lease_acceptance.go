package accounting

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"errors"
	"time"

	"github.com/ElXnet/ElX-control/internal/elxcontrol/corepolicy"
	"github.com/google/uuid"
)

// persistRemoteLeaseAcceptance records the core's actual, still-active
// limiter lease under the very same PostgreSQL transaction as signed usage
// and pressure. A signed proof is NOT authority to adjust a rate grant.
//
// A newer telemetry sample without lease proof cannot accidentally inherit a
// prior acceptance: the acceptance is pinned to its pressure sequence.
// Missing, rekeyed or changing grants do not gain new acceptance.
func persistRemoteLeaseAcceptance(ctx context.Context, tx *sql.Tx, binding RemoteBinding,
	period uuid.UUID, pressure corepolicy.PressureSample,
	accepted corepolicy.AcceptedLease, pinnedKey ed25519.PublicKey) error {
	if accepted.NodeID != binding.NodeID ||
		accepted.Incarnation != binding.Incarnation ||
		accepted.Incarnation != pressure.Incarnation ||
		accepted.Revision != pressure.Revision ||
		accepted.AppliedUp <= 0 || accepted.AppliedDown <= 0 ||
		uint64(accepted.AppliedUp) != pressure.RateUp ||
		uint64(accepted.AppliedDown) != pressure.RateDown {
		return ErrRemoteEvidence
	}

	var resource uuid.UUID
	err := tx.QueryRowContext(ctx, `SELECT a.resource_id
		FROM elx_accounting_assignments a
		WHERE a.node_id=$1 AND a.executor_id=$2 AND a.incarnation=$3
		  AND a.accounting_id=$4 AND a.generation=$5 AND a.period_id=$6
		  AND a.active AND a.resource_id IS NOT NULL FOR SHARE`,
		binding.NodeID,binding.ExecutorID,binding.Incarnation,
		binding.AccountingID,binding.Generation,period).Scan(&resource)
	if errors.Is(err, sql.ErrNoRows) {
		// The legacy unbound accounting stream remains billable. It cannot
		// contribute a signed allocator lease or rate-pressure demand.
		return nil
	}
	if err != nil { return err }
	var committedUp, committedDown, policyRevision int64
	var signingKey []byte
	var pending, rotating bool
	err = tx.QueryRowContext(ctx, `SELECT g.committed_up,g.committed_down,
		t.revision+1,g.barrier_public_key,
		EXISTS(SELECT 1 FROM elx_rate_moves m WHERE m.node_id=g.node_id
		  AND m.resource_id=g.resource_id AND NOT m.finalized),
		EXISTS(SELECT 1 FROM elx_core_rotations rot WHERE rot.node_id=g.node_id
		  AND rot.state='quiescing')
		FROM elx_rate_grants g
		JOIN elx_operation_targets t USING(node_id,resource_id)
		JOIN elx_entitlements e ON e.id=g.entitlement_id
		WHERE g.node_id=$1 AND g.resource_id=$2
		  AND e.enabled AND e.valid_until>clock_timestamp()
		  AND NOT EXISTS(SELECT 1 FROM elx_core_identities c
		    WHERE c.node_id=g.node_id AND c.incarnation=$3
		      AND c.revoked=true)`,
		binding.NodeID,resource,binding.Incarnation).
		Scan(&committedUp,&committedDown,&policyRevision,&signingKey,&pending,&rotating)
	if errors.Is(err,sql.ErrNoRows) { return nil }
	if err!=nil { return err }
	if pending || rotating || !bytes.Equal(pinnedKey,signingKey) ||
		committedUp!=accepted.AppliedUp || committedDown!=accepted.AppliedDown ||
		uint64(policyRevision)!=accepted.Revision {
		return nil
	}
	// Ensure this EXACT pressure sequence is already durably accepted in
	// the same transaction. Never trust an issued lease independently.
	var sequence int64
	err=tx.QueryRowContext(ctx,`SELECT sequence FROM elx_rate_pressure_samples
		WHERE node_id=$1 AND resource_id=$2 AND incarnation=$3
		  AND core_revision=$4 AND policy_up=$5 AND policy_down=$6
		  FOR UPDATE`,binding.NodeID,resource,binding.Incarnation,
		policyRevision,committedUp,committedDown).Scan(&sequence)
	if errors.Is(err,sql.ErrNoRows) { return nil }
	if err!=nil { return err }
	if pressure.Sequence!=uint64(sequence) { return nil }
	var oldSeq int64
	err=tx.QueryRowContext(ctx,`SELECT lease_sequence FROM elx_rate_lease_acceptances
		WHERE node_id=$1 AND resource_id=$2 FOR UPDATE`,
		binding.NodeID,resource).Scan(&oldSeq)
	if err!=nil && !errors.Is(err,sql.ErrNoRows) { return err }
	if err==nil && accepted.Sequence < oldSeq { return ErrRemoteEvidence }
	var currentTime time.Time
	if err = tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&currentTime); err != nil {
		return err
	}
	if !accepted.ExpiresAt.After(currentTime.Add(2 * time.Second)) {
		return ErrRemoteEvidence
	}
	_,err=tx.ExecContext(ctx,`INSERT INTO elx_rate_lease_acceptances
	  (node_id,resource_id,incarnation,pressure_sequence,lease_sequence,
	  lease_expires_at,policy_revision,policy_up,policy_down,
	  ceiling_up,ceiling_down,received_at)
	  VALUES($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,clock_timestamp())
	  ON CONFLICT(node_id,resource_id) DO UPDATE SET
	    incarnation=EXCLUDED.incarnation,
	    pressure_sequence=EXCLUDED.pressure_sequence,
	    lease_sequence=EXCLUDED.lease_sequence,
	    lease_expires_at=EXCLUDED.lease_expires_at,
	    policy_revision=EXCLUDED.policy_revision,
	    policy_up=EXCLUDED.policy_up,policy_down=EXCLUDED.policy_down,
	    ceiling_up=EXCLUDED.ceiling_up,ceiling_down=EXCLUDED.ceiling_down,
	    received_at=EXCLUDED.received_at`,
	  binding.NodeID,resource,binding.Incarnation,sequence,accepted.Sequence,
	  accepted.ExpiresAt,policyRevision,committedUp,committedDown,
	  accepted.CeilingUp,accepted.CeilingDown)
	return err
}
