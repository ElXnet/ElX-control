package journal

import (
	"crypto/ed25519"
	"database/sql"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/ElXnet/ElX-control/internal/elxcontrol/corepolicy"
	"github.com/google/uuid"
)

func TestStage4TechnicalProfileReservationIsDurableButNotAdmitted(t *testing.T) {
	ctx, db := testDatabase(t)
	entitlement := uuid.NewString()
	target := Target{NodeID: uuid.NewString(), ResourceID: uuid.NewString()}
	executor, storeID := uuid.NewString(), uuid.NewString()
	_, err := db.ExecContext(ctx, `INSERT INTO elx_entitlements(id,active_slots,valid_until)
	    VALUES($1,1,clock_timestamp()+interval '1 hour')`, entitlement)
	checkError(t, err, nil)
	_, err = db.ExecContext(ctx, `INSERT INTO elx_rate_budgets(entitlement_id,up_limit,down_limit)
	    VALUES($1,100,100)`, entitlement)
	checkError(t, err, nil)
	_, err = db.ExecContext(ctx, `INSERT INTO elx_operation_targets(node_id,resource_id)
	    VALUES($1,$2)`, target.NodeID, target.ResourceID)
	checkError(t, err, nil)
	public, _, err := ed25519.GenerateKey(nil)
	checkError(t, err, nil)
	_, err = db.ExecContext(ctx, `INSERT INTO elx_rate_grants
	    (entitlement_id,node_id,resource_id,committed_up,committed_down,epoch,barrier_public_key)
	    VALUES($1,$2,$3,100,100,9,$4)`,
		entitlement, target.NodeID, target.ResourceID, []byte(public))
	checkError(t, err, nil)
	checkError(t, ProvisionCoreStoreWitness(ctx, db, CoreStoreWitness{
		NodeID: target.NodeID, ResourceID: target.ResourceID,
		ExecutorID: executor, StoreID: storeID,
		AuthorityGeneration: 9, CoreRevision: 1,
	}), nil)

	now := time.Now().UTC().Unix()
	grant := corepolicy.ProfileGrantIntent{
		Version: 1, Action: "prepare",
		OperationID: uuid.New(), NodeID: uuid.MustParse(target.NodeID),
		ResourceID: uuid.MustParse(target.ResourceID), ExecutorID: uuid.MustParse(executor),
		ProfileID: uuid.New(), SubscriptionID: "lab", Email: "device@lab",
		InboundTag: "vless-reality-01",
		ProfileGeneration: 1, AuthorityGeneration: 9, PolicyRevision: 1,
		NotBefore: now - 2, NotAfter: now + 30,
	}
	req := ProfileReservation{Grant: grant, EntitlementID: entitlement,
		PinnedSubscription: "lab"}
	first, err := QueueTechnicalProfile(ctx, db, req)
	if err != nil || first.State != "INTENT" || first.AlreadyQueued {
		t.Fatalf("first operation was not durably reserved: %+v %v", first, err)
	}
	retry, err := QueueTechnicalProfile(ctx, db, req)
	if err != nil || !retry.AlreadyQueued || retry.Digest != first.Digest {
		t.Fatalf("same signed intent failed idempotency: %+v %v", retry, err)
	}
	var phase, operationState string
	err = db.QueryRowContext(ctx, `SELECT p.state,o.state
	    FROM elx_technical_profiles p
	    JOIN elx_technical_profile_operations o ON o.operation_id=p.operation_id
	    WHERE p.profile_id=$1`, grant.ProfileID).Scan(&phase, &operationState)
	if err != nil || phase != "prepared" || operationState != "INTENT" {
		t.Fatalf("prepared user was unexpectedly installed or admitted: phase=%s op=%s err=%v",
			phase, operationState, err)
	}
	issued, err := NextTechnicalProfile(ctx, db, target, executor, "lab")
	if err != nil || issued.OperationID != grant.OperationID ||
		issued.NotAfter != grant.NotAfter || issued.NotBefore != grant.NotBefore ||
		issued.ProfileID != grant.ProfileID || issued.ExecutorID != grant.ExecutorID ||
		string(issued.Transcript()) != string(grant.Transcript()) {
		t.Fatalf("Control read-only job was not byte-for-byte signed scope: %+v %v", issued, err)
	}
	if _, err := NextTechnicalProfile(ctx, db, target, uuid.NewString(), "lab"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("foreign executor could fetch pending signed profile: %v", err)
	}
	if _, err := NextTechnicalProfile(ctx, db, target, executor, "other"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("foreign subscription could fetch pending profile: %v", err)
	}
	stolen := req
	stolen.Grant.OperationID = grant.OperationID
	stolen.Grant.ProfileID = uuid.New()
	if _, err := QueueTechnicalProfile(ctx, db, stolen); !errors.Is(err, ErrProfileConflict) {
		t.Fatalf("operationId reused for foreign profile: %v", err)
	}
	stolen = req
	stolen.Grant.OperationID = uuid.New()
	stolen.Grant.ProfileID = grant.ProfileID
	if _, err := QueueTechnicalProfile(ctx, db, stolen); !errors.Is(err, ErrProfileConflict) {
		t.Fatalf("retired-or-active VLESS UUID reused: %v", err)
	}
	wrong := req
	wrong.Grant.OperationID = uuid.New()
	wrong.Grant.ProfileID = uuid.New()
	wrong.Grant.ExecutorID = uuid.New()
	if _, err := QueueTechnicalProfile(ctx, db, wrong); !errors.Is(err, ErrProfileAuthority) {
		t.Fatalf("foreign executor obtained profile reservation: %v", err)
	}
	wrong = req
	wrong.Grant.OperationID = uuid.New()
	wrong.Grant.ProfileID = uuid.New()
	wrong.Grant.AuthorityGeneration = 8
	if _, err := QueueTechnicalProfile(ctx, db, wrong); !errors.Is(err, ErrProfileAuthority) {
		t.Fatalf("old authority obtained profile reservation: %v", err)
	}
	wrong = req
	wrong.Grant.OperationID = uuid.New()
	wrong.Grant.ProfileID = uuid.New()
	wrong.Grant.PolicyRevision = 2
	if _, err := QueueTechnicalProfile(ctx, db, wrong); !errors.Is(err, ErrProfileAuthority) {
		t.Fatalf("future uncommitted core revision obtained reservation: %v", err)
	}
	wrong = req
	wrong.PinnedSubscription = "other"
	if _, err := QueueTechnicalProfile(ctx, db, wrong); !errors.Is(err, ErrInvalid) {
		t.Fatalf("untrusted subscription selector obtained reservation: %v", err)
	}
	var wg sync.WaitGroup
	results := make(chan error, 2)
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			again := req
			again.Grant.OperationID = uuid.New()
			again.Grant.ProfileID = uuid.New()
			_, runErr := QueueTechnicalProfile(ctx, db, again)
			results <- runErr
		}()
	}
	wg.Wait()
	close(results)
	for result := range results {
		if !errors.Is(result, ErrProfileConflict) {
			t.Fatalf("concurrent profile alias bypassed existing email/tag exclusion: %v", result)
		}
	}
}
