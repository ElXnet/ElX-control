package journal

import (
	"crypto/ed25519"
	"crypto/sha256"
	"testing"

	"github.com/google/uuid"
)

func TestRateBudgetHoldsDecreaseUntilBarrier(t *testing.T) {
	ctx, db := testDatabase(t)
	entitlement, resource := uuid.NewString(), uuid.NewString()
	a, b, c := Target{uuid.NewString(), resource}, Target{uuid.NewString(), resource}, Target{uuid.NewString(), resource}
	_, err := db.ExecContext(ctx, `INSERT INTO elx_entitlements(id,active_slots,valid_until)
		VALUES ($1,2,clock_timestamp()+interval '1 hour')`, entitlement)
	checkError(t, err, nil)
	_, err = db.ExecContext(ctx, `INSERT INTO elx_rate_budgets VALUES($1,100,100)`, entitlement)
	checkError(t, err, nil)
	pub, priv, err := ed25519.GenerateKey(nil)
	checkError(t, err, nil)
	for _, x := range []struct {
		target Target
		rate   int
	}{{a, 50}, {b, 50}, {c, 0}} {
		_, err := db.ExecContext(ctx, `INSERT INTO elx_operation_targets(node_id,resource_id) VALUES($1,$2)`, x.target.NodeID, resource)
		checkError(t, err, nil)
		_, err = db.ExecContext(ctx, `INSERT INTO elx_rate_grants
			VALUES($1,$2,$3,$4,$4,1,$5)`, entitlement, x.target.NodeID, resource, x.rate, []byte(pub))
		checkError(t, err, nil)
	}
	reduce, increase, steal := uuid.NewString(), uuid.NewString(), uuid.NewString()
	_, err = Enqueue(ctx, db, a, Command{ID: uuid.NewString(), Payload: []byte("{}")})
	checkError(t, err, ErrManagedRate)
	_, err = QueueRateMove(ctx, db, entitlement, a, reduce, 0, Rate{30, 30})
	checkError(t, err, nil)
	_, err = QueueRateMove(ctx, db, entitlement, a, reduce, 0, Rate{30, 30})
	checkError(t, err, nil)
	_, err = QueueRateMove(ctx, db, entitlement, b, increase, 0, Rate{70, 70})
	checkError(t, err, ErrRateBudget)
	checkError(t, FinalizeRateMove(ctx, db, entitlement, a, reduce, nil), ErrPending)

	cmd, err := Pending(ctx, db, a)
	checkError(t, err, nil)
	hash := sha256.Sum256(cmd.Payload)
	checkError(t, ConfirmApplied(ctx, db, a, reduce, 1, hash), nil)
	checkError(t, FinalizeRateMove(ctx, db, entitlement, a, reduce, nil), ErrRateBarrier)
	_, err = QueueRateMove(ctx, db, entitlement, b, increase, 0, Rate{70, 70})
	checkError(t, err, ErrRateBudget)
	foreignProof := ed25519.Sign(priv, rateBarrierMessage(entitlement, b, reduce, 1, 1, Rate{30, 30}))
	checkError(t, FinalizeRateMove(ctx, db, entitlement, a, reduce, foreignProof), ErrRateBarrier)
	proof := ed25519.Sign(priv, rateBarrierMessage(entitlement, a, reduce, 1, 1, Rate{30, 30}))
	checkError(t, FinalizeRateMove(ctx, db, entitlement, a, reduce, proof), nil)
	checkError(t, FinalizeRateMove(ctx, db, entitlement, a, reduce, proof), nil)

	// Race two operations for the same freed 20 B/s. No ACK is delivered
	// for the winner; its pending commitment must block the loser.
	results := make(chan error, 2)
	go func() {
		_, err := QueueRateMove(ctx, db, entitlement, b, increase, 0, Rate{70, 70})
		results <- err
	}()
	go func() {
		_, err := QueueRateMove(ctx, db, entitlement, c, steal, 0, Rate{20, 20})
		results <- err
	}()
	var accepted, blocked int
	for range 2 {
		switch err := <-results; err {
		case nil:
			accepted++
		case ErrRateBudget:
			blocked++
		default:
			t.Fatal(err)
		}
	}
	if accepted != 1 || blocked != 1 {
		t.Fatalf("accepted=%d blocked=%d", accepted, blocked)
	}
}
