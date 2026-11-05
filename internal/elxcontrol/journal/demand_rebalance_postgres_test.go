package journal

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"
)

func seedDemandRates(t *testing.T, budget Rate, amounts ...Rate) (string, []Target, ed25519.PrivateKey) {
	t.Helper()
	ctx, db := testDatabase(t)
	entitlement := uuid.NewString()
	_, err := db.ExecContext(ctx, `INSERT INTO elx_entitlements(id,active_slots,valid_until)
		VALUES ($1,2,clock_timestamp()+interval '1 hour')`, entitlement)
	checkError(t, err, nil)
	_, err = db.ExecContext(ctx, `INSERT INTO elx_rate_budgets(entitlement_id,up_limit,down_limit)
		VALUES ($1,$2,$3)`, entitlement, budget.Up, budget.Down)
	checkError(t, err, nil)
	public, private, err := ed25519.GenerateKey(nil)
	checkError(t, err, nil)
	targets := make([]Target, 0, len(amounts))
	for _, amount := range amounts {
		target := Target{NodeID: uuid.NewString(), ResourceID: uuid.NewString()}
		_, err = db.ExecContext(ctx, `INSERT INTO elx_operation_targets(node_id,resource_id)
			VALUES ($1,$2)`, target.NodeID, target.ResourceID)
		checkError(t, err, nil)
		_, err = db.ExecContext(ctx, `INSERT INTO elx_rate_grants
			(entitlement_id,node_id,resource_id,committed_up,committed_down,epoch,barrier_public_key)
			VALUES ($1,$2,$3,$4,$5,1,$6)`,
			entitlement, target.NodeID, target.ResourceID, amount.Up, amount.Down, []byte(public))
		checkError(t, err, nil)
		targets = append(targets, target)
	}
	return entitlement, targets, private
}

func trustedDemand(target Target, up, down int64) RateDemand {
	return RateDemand{Target: target, Requested: Rate{Up: up, Down: down},
		Weight: 1, ObservedAt: time.Now().UTC(), LeaseValid: true}
}

func TestDemandRebalanceWaitsForSignedReduction(t *testing.T) {
	ctx, db := testDatabase(t)
	entitlement, targets, private := seedDemandRates(t, Rate{100, 100}, Rate{50, 50}, Rate{50, 50})
	demands := []RateDemand{trustedDemand(targets[0], 30, 30), trustedDemand(targets[1], 70, 70)}
	result, err := RebalanceDemand(ctx, db, entitlement, demands)
	checkError(t, err, nil)
	if result.Phase != "lower" || result.Target != targets[0] || result.Desired != (Rate{30, 30}) || result.OperationID == "" {
		t.Fatalf("expected signed reduction first, got %+v", result)
	}
	retry, err := RebalanceDemand(ctx, db, entitlement, demands)
	checkError(t, err, nil)
	if retry.Phase != "waiting" || retry.OperationID != "" {
		t.Fatalf("pending reduction was bypassed: %+v", retry)
	}
	_, err = QueueRateMove(ctx, db, entitlement, targets[1], uuid.NewString(), 0, Rate{70, 70})
	checkError(t, err, ErrRateBudget)

	cmd, err := Pending(ctx, db, targets[0])
	checkError(t, err, nil)
	checkError(t, ConfirmApplied(ctx, db, targets[0], result.OperationID, 1, sha256.Sum256(cmd.Payload)), nil)
	checkError(t, FinalizeRateMove(ctx, db, entitlement, targets[0], result.OperationID, nil), ErrRateBarrier)
	retry, err = RebalanceDemand(ctx, db, entitlement, demands)
	checkError(t, err, nil)
	if retry.Phase != "waiting" {
		t.Fatalf("ordinary ACK freed reduction budget: %+v", retry)
	}
	proof := ed25519.Sign(private, rateBarrierMessage(entitlement, targets[0], result.OperationID, 1, 1, Rate{30, 30}))
	checkError(t, FinalizeRateMove(ctx, db, entitlement, targets[0], result.OperationID, proof), nil)
	increase, err := RebalanceDemand(ctx, db, entitlement, demands)
	checkError(t, err, nil)
	if increase.Phase != "raise" || increase.Target != targets[1] || increase.Desired != (Rate{70, 70}) {
		t.Fatalf("budget not reassigned after confirmed release: %+v", increase)
	}
	cmd, err = Pending(ctx, db, targets[1])
	checkError(t, err, nil)
	checkError(t, ConfirmApplied(ctx, db, targets[1], increase.OperationID, 1, sha256.Sum256(cmd.Payload)), nil)
	checkError(t, FinalizeRateMove(ctx, db, entitlement, targets[1], increase.OperationID, nil), nil)
	stable, err := RebalanceDemand(ctx, db, entitlement, demands)
	checkError(t, err, nil)
	if stable.Phase != "stable" || stable.OperationID != "" {
		t.Fatalf("final rates were not stable: %+v", stable)
	}
}

func TestDemandRebalancePreservesUnknownAndStaleGrants(t *testing.T) {
	ctx, db := testDatabase(t)
	entitlement, targets, _ := seedDemandRates(t, Rate{100, 100}, Rate{70, 40}, Rate{30, 60})
	// Only the second target is safely observable; the absent target still
	// owns all 70/40 bytes per second of committed capacity.
	out, err := RebalanceDemand(ctx, db, entitlement, []RateDemand{trustedDemand(targets[1], 100, 100)})
	checkError(t, err, nil)
	if out.Phase != "stable" || out.FrozenTargets != 1 {
		t.Fatalf("unknown target accidentally released budget: %+v", out)
	}
	stale := trustedDemand(targets[0], 1, 1)
	stale.ObservedAt = time.Now().Add(-time.Minute)
	out, err = RebalanceDemand(ctx, db, entitlement, []RateDemand{stale, trustedDemand(targets[1], 100, 100)})
	checkError(t, err, nil)
	if out.Phase != "stable" || out.FrozenTargets != 1 {
		t.Fatalf("stale sample was trusted: %+v", out)
	}
	// If an existing frozen commitment is larger than a newly tightened
	// budget, only a provable online grant may be reduced.
	_, err = db.ExecContext(ctx, "UPDATE elx_rate_budgets SET up_limit=40,down_limit=40 WHERE entitlement_id=$1", entitlement)
	checkError(t, err, nil)
	out, err = RebalanceDemand(ctx, db, entitlement, []RateDemand{trustedDemand(targets[1], 100, 100)})
	checkError(t, err, nil)
	if !out.FrozenOverBudget || out.Phase != "lower" || out.Target != targets[1] || out.Desired != (Rate{}) {
		t.Fatalf("over-budget frozen commitment must not raise: %+v", out)
	}
}

func TestDemandRebalanceRejectsUnknownAndDuplicateTargets(t *testing.T) {
	ctx, db := testDatabase(t)
	entitlement, targets, _ := seedDemandRates(t, Rate{100, 100}, Rate{50, 50})
	valid := trustedDemand(targets[0], 100, 100)
	invalidCases := [][]RateDemand{
		{valid, valid},
		{trustedDemand(Target{NodeID: uuid.NewString(), ResourceID: uuid.NewString()}, 100, 100)},
		{{Target: targets[0], Requested: Rate{-1, 1}, Weight: 1}},
		{{Target: targets[0], Requested: Rate{1, 1}, Weight: 0}},
	}
	for index, observations := range invalidCases {
		if _, err := RebalanceDemand(ctx, db, entitlement, observations); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid input %d was accepted: %v", index, err)
		}
	}
	zero := trustedDemand(targets[0], 0, 0)
	result, err := RebalanceDemand(ctx, db, entitlement, []RateDemand{zero})
	checkError(t, err, nil)
	if result.Phase != "stable" || result.FrozenTargets != 1 {
		t.Fatalf("idle VPN was disabled by zero observed traffic: %+v", result)
	}
}
