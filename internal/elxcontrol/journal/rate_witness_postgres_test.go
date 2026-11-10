package journal

import (
	"crypto/sha256"
	"testing"

	"github.com/google/uuid"
)

// Exact PostgreSQL schema-level regression for the signed-lease / pending
// scheduler deadlock. The store HWM is core policy revision 1 while the
// pending journal's FIRST operation revision is also 1: its application
// would move the core to policy revision 2, not prove it already applied.
func TestPendingRateMoveMayReceiveOnlyPreviousCommittedStoreWitness(t *testing.T) {
	ctx, db := testDatabase(t)
	entitlement, targets, _ := seedDemandRates(t, ctx, db,
		Rate{Up: 200, Down: 200}, Rate{Up: 100, Down: 100})
	target := targets[0]
	const epoch int64 = 1
	executor, store := uuid.NewString(), uuid.NewString()
	checkError(t, ProvisionCoreStoreWitness(ctx, db, CoreStoreWitness{
		NodeID: target.NodeID, ResourceID: target.ResourceID,
		ExecutorID: executor, StoreID: store,
		AuthorityGeneration: uint64(epoch), CoreRevision: 1,
	}), nil)
	operation := uuid.NewString()
	if ok, err := PendingRateWitnessEligible(ctx, db, target, operation, epoch); err != nil || ok {
		t.Fatalf("unknown operation received store witness: %v %v", ok, err)
	}
	if _, err := QueueRateMove(ctx, db, entitlement, target, operation, 0,
		Rate{Up: 80, Down: 80}); err != nil {
		t.Fatal(err)
	}
	allowed, err := PendingRateWitnessEligible(ctx, db, target, operation, epoch)
	if err != nil || !allowed {
		t.Fatalf("durably reserved next core rate cannot refresh prior-revision HWM: %v %v", allowed, err)
	}
	for _, test := range []struct {
		name string
		op string
		epoch int64
	}{
		{"foreign-operation", uuid.NewString(), epoch},
		{"stale-epoch", operation, epoch+1},
	} {
		ok, err := PendingRateWitnessEligible(ctx, db, target, test.op, test.epoch)
		if err != nil || ok {
			t.Fatalf("%s bypassed signed witness binding: %v %v", test.name, ok, err)
		}
	}
	cmd, err := Pending(ctx, db, target)
	if err != nil {
		t.Fatal(err)
	}
	if err := ConfirmApplied(ctx, db, target, operation, 1,
		sha256.Sum256(cmd.Payload)); err != nil {
		t.Fatal(err)
	}
	eligible, err := PendingRateWitnessEligible(ctx, db, target, operation, epoch)
	if err != nil || eligible {
		t.Fatalf("already applied/unknown result was treated as pending previous HWM: %v %v", eligible, err)
	}
}
