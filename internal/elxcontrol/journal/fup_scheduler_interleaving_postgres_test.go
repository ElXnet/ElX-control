package journal

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"testing"
	"time"

	"github.com/google/uuid"
)

// finalizeSignedFUPReduction performs the same separation as the real
// Control agent: applied policy receipt first, distinct ElXray barrier next.
// Merely ACKing an operation never releases its old committed rate.
func finalizeSignedFUPReduction(t *testing.T, ctx context.Context, db *sql.DB,
	entitlement string, target Target, operationID string, revision int64,
	desired Rate, signer ed25519.PrivateKey) {
	t.Helper()
	cmd, err := Pending(ctx, db, target)
	checkError(t, err, nil)
	if cmd.ID != operationID {
		t.Fatalf("unexpected pending operation: got %s, want %s", cmd.ID, operationID)
	}
	checkError(t, ConfirmApplied(ctx, db, target, operationID,
		revision, sha256.Sum256(cmd.Payload)), nil)
	checkError(t, FinalizeRateMove(ctx, db, entitlement, target,
		operationID, nil), ErrRateBarrier)
	proof := ed25519.Sign(signer, rateBarrierMessage(
		entitlement, target, operationID, 1, revision, desired))
	checkError(t, FinalizeRateMove(ctx, db, entitlement, target,
		operationID, proof), nil)
}

func readCommittedFUPRates(t *testing.T, ctx context.Context, db *sql.DB,
	entitlement string) Rate {
	t.Helper()
	var r Rate
	err := db.QueryRowContext(ctx, `SELECT COALESCE(sum(committed_up),0),
		COALESCE(sum(committed_down),0) FROM elx_rate_grants
		WHERE entitlement_id=$1`, entitlement).Scan(&r.Up, &r.Down)
	checkError(t, err, nil)
	return r
}

// Test: an active FUP cap arrives after an attested demand scheduler has
// queued a reduction but BEFORE a core-signed barrier confirms the release.
// Another node must not be allowed to receive its old planned increase.
// ReconcileFUP must reduce both grants without losing the pending journal
// operation, and the scheduler must not exceed the strictest FUP limit.
func TestFUPTighteningInterleavesWithAttestedSchedulerAndSignedBarriers(t *testing.T) {
	ctx, db := testDatabase(t)
	entitlement, targets, signer := seedDemandRates(t, ctx, db,
		Rate{100000, 100000}, Rate{50000, 50000}, Rate{50000, 50000})
	key := signer.Public().(ed25519.PublicKey)
	sampled := time.Now().UTC().Add(-time.Second)
	seedAttestedRateTarget(t, ctx, db, entitlement, targets[0],
		key, uuid.New(), sampled, false)
	seedAttestedRateTarget(t, ctx, db, entitlement, targets[1],
		key, uuid.New(), sampled, true)
	leader, err := AcquireSchedulerLease(ctx, db, entitlement, uuid.New(),
		15*time.Second)
	checkError(t, err, nil)

	first, err := RebalanceAttestedDemand(ctx, db, entitlement, leader)
	checkError(t, err, nil)
	if first.Phase != "lower" || first.OperationID == "" ||
		first.Target != targets[0] ||
		first.Desired != (Rate{32768, 32768}) {
		t.Fatalf("unexpected initial signed scheduler reduction: %+v", first)
	}

	// Model the durable result of a signed FUP threshold crossing. The FUP
	// event is stored in the same table used by real signed-usage ingestion.
	period := uuid.New()
	_, err = db.ExecContext(ctx, `INSERT INTO elx_usage_periods
		(id,entitlement_id,starts_at,ends_at,direction,threshold_bytes,
		 reduced_up,reduced_down)
		VALUES($1,$2,clock_timestamp()-interval '1 minute',
		 clock_timestamp()+interval '1 hour','total',1,40000,40000)`,
		period, entitlement)
	checkError(t, err, nil)
	_, err = db.ExecContext(ctx, `INSERT INTO elx_fup_events
		(period_id,reduced_up,reduced_down) VALUES($1,40000,40000)`, period)
	checkError(t, err, nil)

	wait, err := RebalanceAttestedDemand(ctx, db, entitlement, leader)
	checkError(t, err, nil)
	if wait.OperationID != "" || wait.Phase != "waiting" {
		t.Fatalf("scheduler bypassed pending signed reduction after FUP: %+v", wait)
	}
	if _, err := QueueRateMove(ctx, db, entitlement, targets[1],
		uuid.NewString(), 0, Rate{67232, 67232}); err != ErrRateBudget {
		t.Fatalf("stale pre-FUP raise was not denied: %v", err)
	}

	// Node0 has a pending lower barrier; node1 can independently queue its
	// own FUP reduction but cannot release old capacity on ordinary ACK.
	reconcile, err := ReconcileFUP(ctx, db, entitlement)
	checkError(t, err, nil)
	if !reconcile.Active || reconcile.Queued != 1 || reconcile.Pending != 1 {
		t.Fatalf("FUP did not preserve pending reduction: %+v", reconcile)
	}
	busy, err := Pending(ctx, db, targets[1])
	checkError(t, err, nil)
	finalizeSignedFUPReduction(t, ctx, db, entitlement, targets[1],
		busy.ID, 1, Rate{20000, 20000}, signer)
	// A pending scheduler barrier still consumes its old 50k commitment.
	if got := readCommittedFUPRates(t, ctx, db, entitlement);
		got != (Rate{70000, 70000}) {
		t.Fatalf("unproved node0 grant prematurely released: %+v", got)
	}
	finalizeSignedFUPReduction(t, ctx, db, entitlement, targets[0],
		first.OperationID, 1, first.Desired, signer)

	// FUP reconciles again, reducing node0 from 32768 to 20000. The
	// desired final 20k+20k must not be committed until the second barrier.
	reconcile, err = ReconcileFUP(ctx, db, entitlement)
	checkError(t, err, nil)
	if !reconcile.Active || reconcile.Queued != 1 || reconcile.Pending != 0 {
		t.Fatalf("FUP second pass failed to converge: %+v", reconcile)
	}
	final, err := Pending(ctx, db, targets[0])
	checkError(t, err, nil)
	finalizeSignedFUPReduction(t, ctx, db, entitlement, targets[0],
		final.ID, 2, Rate{20000, 20000}, signer)
	if got := readCommittedFUPRates(t, ctx, db, entitlement);
		got != (Rate{40000, 40000}) {
		t.Fatalf("effective FUP cap violated after signed convergence: %+v", got)
	}
	stable, err := ReconcileFUP(ctx, db, entitlement)
	checkError(t, err, nil)
	if !stable.Active || stable.Queued != 0 || stable.Pending != 0 {
		t.Fatalf("FUP reconciliation not idempotent: %+v", stable)
	}
	result, err := RebalanceAttestedDemand(ctx, db, entitlement, leader)
	checkError(t, err, nil)
	if result.OperationID != "" || result.Phase == "raise" {
		t.Fatalf("scheduler restored purchased speed over active FUP: %+v", result)
	}
}
