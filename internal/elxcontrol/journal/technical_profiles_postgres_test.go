package journal

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
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
	// INSTALL is a second, independently signed durable operation. Its
	// reservation cannot make the prepared profile an admitted VLESS user.
	install := grant
	install.Version = 2
	install.Action = "install"
	install.Flow = "xtls-rprx-vision"
	install.OperationID = uuid.New()
	installReq := InstallReservation{
		Grant: install, EntitlementID: entitlement, PinnedSubscription: "lab",
	}
	installFirst, err := QueueTechnicalInstall(ctx, db, installReq)
	if err != nil || installFirst.State != "INTENT" || installFirst.AlreadyQueued {
		t.Fatalf("signed INSTALL was not queued separately: %+v %v", installFirst, err)
	}
	installRetry, err := QueueTechnicalInstall(ctx, db, installReq)
	if err != nil || !installRetry.AlreadyQueued || installRetry.Digest != installFirst.Digest {
		t.Fatalf("signed INSTALL idempotency failed: %+v %v", installRetry, err)
	}
	pendingInstall, err := NextTechnicalInstall(ctx, db, target, executor, "lab")
	if err != nil || pendingInstall.Flow != install.Flow ||
		pendingInstall.Version != 2 || pendingInstall.Action != "install" ||
		string(pendingInstall.Transcript()) != string(install.Transcript()) {
		t.Fatalf("pending INSTALL changed signed fields: %+v %v", pendingInstall, err)
	}
	if _, err := NextTechnicalInstall(ctx, db, target, uuid.NewString(), "lab"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("foreign executor read another installation: %v", err)
	}
	if _, err := NextTechnicalInstall(ctx, db, target, executor, "other"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("foreign subscription read another installation: %v", err)
	}
	conflictingInstall := installReq
	conflictingInstall.Grant.OperationID = uuid.New()
	if _, err := QueueTechnicalInstall(ctx, db, conflictingInstall); !errors.Is(err, ErrProfileConflict) {
		t.Fatalf("second INSTALL reserved same profile: %v", err)
	}
	var afterInstallPhase string
	if err := db.QueryRowContext(ctx, `SELECT state FROM elx_technical_profiles WHERE profile_id=$1`,
		grant.ProfileID).Scan(&afterInstallPhase); err != nil || afterInstallPhase != "prepared" {
		t.Fatalf("unsigned central INSTALL incorrectly admitted profile: %s %v", afterInstallPhase, err)
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
	// UUIDs with different middle bytes can resolve to the same VLESS
	// authenticated user: ProcessUUID zeroes bytes 6 and 7. No
	// alternate email/inbound may reserve such an impersonating alias.
	alias := req
	alias.Grant.OperationID = uuid.New()
	alias.Grant.ProfileID = grant.ProfileID
	alias.Grant.ProfileID[6] ^= 1
	alias.Grant.ProfileID[7] ^= 2
	alias.Grant.Email = "alias@lab"
	alias.Grant.InboundTag = "other-vless-inbound"
	if alias.Grant.ProfileID == grant.ProfileID {
		t.Fatal("VLESS alias test did not change the printed profile UUID")
	}
	if _, err := QueueTechnicalProfile(ctx, db, alias); !errors.Is(err, ErrProfileConflict) {
		t.Fatalf("normalized VLESS UUID alias could reserve a second profile: %v", err)
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

	// Only independently pinned core public key, persistent store and boot
	// may advance an INSTALL to APPLIED. A copied/agent-fabricated readback
	// never changes the authoritative PostgreSQL operation state.
	boot := uuid.New()
	corePublic, corePrivate, err := ed25519.GenerateKey(nil)
	checkError(t, err, nil)
	_, err = db.ExecContext(ctx, `INSERT INTO elx_core_identities(node_id,incarnation,public_key)
		VALUES($1,$2,$3)`, target.NodeID, boot, corePublic)
	checkError(t, err, nil)
	_, err = db.ExecContext(ctx, `UPDATE elx_core_store_witnesses
		SET core_incarnation=$1,last_operation_id=$2
		WHERE node_id=$3 AND resource_id=$4`,
		boot, install.OperationID, target.NodeID, target.ResourceID)
	checkError(t, err, nil)
	proofHash := sha256.Sum256(install.Transcript())
	proof := corepolicy.InstallReceipt{
		Version: 1, OperationID: install.OperationID, ProfileID: install.ProfileID,
		NodeID: install.NodeID, ResourceID: install.ResourceID,
		ExecutorID: install.ExecutorID, StoreID: uuid.MustParse(storeID),
		CoreIncarnation: boot, AuthorityGeneration: install.AuthorityGeneration,
		PolicyRevision: install.PolicyRevision,
		TranscriptSHA256: hex.EncodeToString(proofHash[:]),
	}
	proof.Signature = ed25519.Sign(corePrivate, proof.Transcript())
	badProof := proof
	badProof.Signature = append([]byte(nil), proof.Signature...)
	badProof.Signature[0] ^= 1
	if err := ConfirmTechnicalInstalled(ctx, db, badProof); !errors.Is(err, corepolicy.ErrInstallProof) {
		t.Fatalf("forged installed evidence advanced PostgreSQL: %v", err)
	}
	badProof = proof
	badProof.CoreIncarnation = uuid.New()
	badProof.Signature = ed25519.Sign(corePrivate, badProof.Transcript())
	if err := ConfirmTechnicalInstalled(ctx, db, badProof); !errors.Is(err, corepolicy.ErrInstallProof) {
		t.Fatalf("unwitnessed new core boot advanced technical install: %v", err)
	}
	if err := db.QueryRowContext(ctx, `SELECT state FROM elx_technical_profiles WHERE profile_id=$1`,
		install.ProfileID).Scan(&afterInstallPhase); err != nil || afterInstallPhase != "prepared" {
		t.Fatalf("forged installed proof changed technical profile: %s %v", afterInstallPhase, err)
	}
	if err := ConfirmTechnicalInstalled(ctx, db, proof); err != nil {
		t.Fatalf("pinned signed installed receipt did not commit: %v", err)
	}
	if err := ConfirmTechnicalInstalled(ctx, db, proof); err != nil {
		t.Fatalf("idempotent signed installed receipt replay failed: %v", err)
	}
	var finalProfile, finalOp string
	err = db.QueryRowContext(ctx, `SELECT p.state,o.state FROM elx_technical_profiles p
	    JOIN elx_technical_profile_operations o ON o.profile_id=p.profile_id
	    WHERE p.profile_id=$1 AND o.operation_id=$2`,
		install.ProfileID, install.OperationID).Scan(&finalProfile, &finalOp)
	if err != nil || finalProfile != "installed" || finalOp != "APPLIED" {
		t.Fatalf("core-signed INSTALLED receipt was not atomic: profile=%s operation=%s err=%v",
			finalProfile, finalOp, err)
	}
	// A later signed v2 RETIRE first reserves a distinct operation, without
	// releasing any session owner or the node's existing bandwidth grant.
	retire := install
	retire.Action = "retire"
	retire.OperationID = uuid.New()
	retire.ProfileGeneration = 2
	retireReq := RetireReservation{
		Grant: retire, EntitlementID: entitlement, PinnedSubscription: "lab",
	}
	reserved, err := QueueTechnicalRetire(ctx, db, retireReq)
	if err != nil || reserved.State != "INTENT" || reserved.AlreadyQueued {
		t.Fatalf("signed RETIRE was not persisted: %+v %v", reserved, err)
	}
	retryRetire, err := QueueTechnicalRetire(ctx, db, retireReq)
	if err != nil || !retryRetire.AlreadyQueued || retryRetire.Digest != reserved.Digest {
		t.Fatalf("signed RETIRE idempotency failed: %+v %v", retryRetire, err)
	}
	sentRetire, err := NextTechnicalRetire(ctx, db, target, executor, "lab")
	if err != nil || string(sentRetire.Transcript()) != string(retire.Transcript()) {
		t.Fatalf("Control RETIRE delivery was not exact: %+v %v", sentRetire, err)
	}
	if _, err := NextTechnicalRetire(ctx, db, target, uuid.NewString(), "lab"); !errors.Is(err, sql.ErrNoRows) {
		t.Fatalf("wrong executor could read signed RETIRE: %v", err)
	}
	retireCollision := retireReq
	retireCollision.Grant.OperationID = uuid.New()
	if _, err := QueueTechnicalRetire(ctx, db, retireCollision); !errors.Is(err, ErrProfileConflict) {
		t.Fatalf("second RETIRE unexpectedly acquired old VLESS profile: %v", err)
	}
	retireHash := sha256.Sum256(retire.Transcript())
	retireProof := corepolicy.RetireReceipt{
		Version: 1, OperationID: retire.OperationID, ProfileID: retire.ProfileID,
		NodeID: retire.NodeID, ResourceID: retire.ResourceID,
		ExecutorID: retire.ExecutorID, StoreID: uuid.MustParse(storeID),
		CoreIncarnation: boot, AuthorityGeneration: retire.AuthorityGeneration,
		PolicyRevision: retire.PolicyRevision, RetireGeneration: retire.ProfileGeneration,
		TranscriptSHA256: hex.EncodeToString(retireHash[:]),
	}
	retireProof.Signature = ed25519.Sign(corePrivate, retireProof.Transcript())
	forgedRetire := retireProof
	forgedRetire.Signature = append([]byte(nil), retireProof.Signature...)
	forgedRetire.Signature[0] ^= 1
	if err := ConfirmTechnicalRetired(ctx, db, forgedRetire); !errors.Is(err, corepolicy.ErrRetireProof) {
		t.Fatalf("forged RETIRE proof changed central operation: %v", err)
	}
	if err := ConfirmTechnicalRetired(ctx, db, retireProof); err != nil {
		t.Fatalf("pinned signed RETIRED proof was rejected: %v", err)
	}
	if err := ConfirmTechnicalRetired(ctx, db, retireProof); err != nil {
		t.Fatalf("exact signed RETIRED retry was not idempotent: %v", err)
	}
	var finalRetire, finalRetireOp string
	err = db.QueryRowContext(ctx, `SELECT p.state,o.state
	  FROM elx_technical_profiles p JOIN elx_technical_profile_operations o ON o.profile_id=p.profile_id
	  WHERE p.profile_id=$1 AND o.operation_id=$2`,
		retire.ProfileID, retire.OperationID).Scan(&finalRetire, &finalRetireOp)
	if err != nil || finalRetire != "retired" || finalRetireOp != "APPLIED" {
		t.Fatalf("signed RETIRE did not advance atomically: %s %s %v",
			finalRetire, finalRetireOp, err)
	}
	var preservedUp, preservedDown, owners int64
	err = db.QueryRowContext(ctx, `SELECT g.committed_up,g.committed_down,e.active_slots
	  FROM elx_rate_grants g JOIN elx_entitlements e ON e.id=g.entitlement_id
	  WHERE g.node_id=$1 AND g.resource_id=$2`, target.NodeID, target.ResourceID).
		Scan(&preservedUp,&preservedDown,&owners)
	if err != nil || preservedUp != 100 || preservedDown != 100 || owners != 1 {
		t.Fatalf("RETIRE incorrectly released bandwidth or owner slots: up=%d down=%d slots=%d err=%v",
			preservedUp,preservedDown,owners,err)
	}
}
