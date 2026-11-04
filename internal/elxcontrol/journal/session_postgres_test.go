package journal

import (
	"crypto/ed25519"
	"errors"
	"testing"

	"github.com/google/uuid"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/session"
)

func TestReserveLastSlotConcurrentAcrossNodes(t *testing.T) {
	ctx, db := testDatabase(t)
	db.SetMaxOpenConns(12)
	entitlement := uuid.New()
	_, err := db.ExecContext(ctx, `INSERT INTO elx_entitlements(id,active_slots,valid_until)
		VALUES ($1,1,clock_timestamp()+interval '1 hour')`, entitlement)
	checkError(t, err, nil)
	nodes := [2]uuid.UUID{uuid.New(), uuid.New()}
	const attempts = 100
	type request struct {
		intent    session.Admission
		challenge session.Challenge
		key       ed25519.PrivateKey
	}
	requests := make([]request, attempts)
	for i := range requests {
		pub, key, err := ed25519.GenerateKey(nil)
		checkError(t, err, nil)
		a := session.Admission{EntitlementID: entitlement, DeviceID: uuid.New(), NodeID: nodes[i%2],
			OperationID: uuid.New(), KeyGeneration: 1, Incarnation: uuid.New(), ProfileID: uuid.New(),
			HandshakeHash: [32]byte{1}, FlowBinding: [32]byte{2}}
		_, err = db.ExecContext(ctx, `INSERT INTO elx_devices(id,entitlement_id,key_generation,public_key)
			VALUES($1,$2,1,$3)`, a.DeviceID, entitlement, []byte(pub))
		checkError(t, err, nil)
		c, err := session.IssueChallenge(ctx, db, a)
		checkError(t, err, nil)
		requests[i] = request{a, c, key}
	}

	submit := func(r request) (session.Owner, error) {
		sig := ed25519.Sign(r.key, session.ProofTranscript(r.intent, r.challenge.Nonce))
		return session.ReserveWithProof(ctx, db, r.intent, r.challenge.Nonce, sig)
	}
	first := requests[0]
	challenge, err := session.IssueChallenge(ctx, db, first.intent)
	checkError(t, err, nil)
	if challenge != first.challenge {
		t.Fatal("challenge changed on retry")
	}
	tampered := first.intent
	tampered.FlowBinding[0]++
	_, err = session.IssueChallenge(ctx, db, tampered)
	checkError(t, err, session.ErrChallengeBusy)
	originalSig := ed25519.Sign(first.key, session.ProofTranscript(first.intent, first.challenge.Nonce))
	_, err = session.ReserveWithProof(ctx, db, tampered, first.challenge.Nonce, originalSig)
	checkError(t, err, session.ErrProof)
	tampered.NodeID = nodes[1]
	signedButNotIssued := first
	signedButNotIssued.intent = tampered
	_, err = submit(signedButNotIssued)
	checkError(t, err, session.ErrProof)
	wrongKey := first
	wrongKey.key = requests[1].key
	_, err = submit(wrongKey)
	checkError(t, err, session.ErrProof)

	type result struct {
		req   request
		owner session.Owner
		err   error
	}
	start := make(chan struct{})
	results := make(chan result, attempts)
	for _, req := range requests {
		go func() {
			<-start
			owner, err := submit(req)
			results <- result{req, owner, err}
		}()
	}
	close(start)
	var winner result
	successes := 0
	for range attempts {
		r := <-results
		if r.err == nil {
			winner = r
			successes++
		} else if !errors.Is(r.err, session.ErrFull) {
			t.Errorf("unexpected reservation failure: %v", r.err)
		}
	}
	if successes != 1 {
		t.Fatalf("reserved %d owners for one slot", successes)
	}
	owner, err := submit(winner.req)
	checkError(t, err, nil)
	if owner != winner.owner || owner.Generation != 1 || owner.State != "reserving" {
		t.Fatalf("unexpected replay result: %+v", owner)
	}
	var remaining int
	err = db.QueryRowContext(ctx, `SELECT count(*) FROM elx_device_challenges WHERE device_id=$1`,
		winner.req.intent.DeviceID).Scan(&remaining)
	checkError(t, err, nil)
	if remaining != 0 {
		t.Fatal("committed challenge remained usable")
	}

	otherNode := winner.req
	if otherNode.intent.NodeID == nodes[0] {
		otherNode.intent.NodeID = nodes[1]
	} else {
		otherNode.intent.NodeID = nodes[0]
	}
	_, err = submit(otherNode)
	checkError(t, err, session.ErrConflict)
	otherNode.intent.OperationID = uuid.New()
	_, err = submit(otherNode)
	checkError(t, err, session.ErrProof)
	otherNode.challenge, err = session.IssueChallenge(ctx, db, otherNode.intent)
	checkError(t, err, nil)
	_, err = submit(otherNode)
	checkError(t, err, session.ErrOwned)

	_, err = db.ExecContext(ctx, `UPDATE elx_session_owners SET state='unknown' WHERE id=$1`, owner.ID)
	checkError(t, err, nil)
	_, err = submit(otherNode)
	checkError(t, err, session.ErrOwned)
	otherDevice := requests[0]
	if otherDevice.intent.DeviceID == winner.req.intent.DeviceID {
		otherDevice = requests[1]
	}
	_, err = submit(otherDevice)
	checkError(t, err, session.ErrFull)
	_, err = db.ExecContext(ctx, `UPDATE elx_device_challenges SET expires_at=clock_timestamp() WHERE device_id=$1`,
		otherDevice.intent.DeviceID)
	checkError(t, err, nil)
	_, err = submit(otherDevice)
	checkError(t, err, session.ErrProof)

	stale := winner.req
	stale.intent.KeyGeneration++
	_, err = submit(stale)
	checkError(t, err, session.ErrDenied)
	corePub, coreKey, err := ed25519.GenerateKey(nil)
	checkError(t, err, nil)
	fence := session.Fence{OwnerID: owner.ID, Generation: owner.Generation,
		NodeID: winner.req.intent.NodeID, Incarnation: winner.req.intent.Incarnation,
		ProfileID: winner.req.intent.ProfileID}
	for _, wrong := range []session.Fence{
		{OwnerID: owner.ID, Generation: owner.Generation + 1, NodeID: fence.NodeID, Incarnation: fence.Incarnation, ProfileID: fence.ProfileID},
		{OwnerID: owner.ID, Generation: owner.Generation, NodeID: otherNode.intent.NodeID, Incarnation: fence.Incarnation, ProfileID: fence.ProfileID},
		{OwnerID: owner.ID, Generation: owner.Generation, NodeID: fence.NodeID, Incarnation: uuid.New(), ProfileID: fence.ProfileID},
		{OwnerID: owner.ID, Generation: owner.Generation, NodeID: fence.NodeID, Incarnation: fence.Incarnation, ProfileID: uuid.New()},
	} {
		err = session.ReleaseAfterFence(ctx, db, wrong, corePub, ed25519.Sign(coreKey, session.FenceTranscript(wrong)))
		checkError(t, err, session.ErrFence)
	}
	err = session.ReleaseAfterFence(ctx, db, fence, corePub, ed25519.Sign(winner.req.key, session.FenceTranscript(fence)))
	checkError(t, err, session.ErrFence)
	_, err = submit(otherNode)
	checkError(t, err, session.ErrOwned)

	sig := ed25519.Sign(coreKey, session.FenceTranscript(fence))
	checkError(t, session.ReleaseAfterFence(ctx, db, fence, corePub, sig), session.ErrFence)
	_, err = db.ExecContext(ctx, `INSERT INTO elx_core_identities(node_id,incarnation,public_key)
		VALUES ($1,$2,$3)`, fence.NodeID, fence.Incarnation, []byte(corePub))
	checkError(t, err, nil)
	foreignPub, foreignKey, err := ed25519.GenerateKey(nil)
	checkError(t, err, nil)
	checkError(t, session.ReleaseAfterFence(ctx, db, fence, foreignPub,
		ed25519.Sign(foreignKey, session.FenceTranscript(fence))), session.ErrFence)
	_, err = db.ExecContext(ctx, `UPDATE elx_core_identities SET revoked=true
		WHERE node_id=$1 AND incarnation=$2`, fence.NodeID, fence.Incarnation)
	checkError(t, err, nil)
	checkError(t, session.ReleaseAfterFence(ctx, db, fence, corePub, sig), session.ErrFence)
	_, err = db.ExecContext(ctx, `UPDATE elx_core_identities SET revoked=false
		WHERE node_id=$1 AND incarnation=$2`, fence.NodeID, fence.Incarnation)
	checkError(t, err, nil)
	checkError(t, session.ReleaseAfterFence(ctx, db, fence, corePub, sig), nil)
	next, err := submit(otherNode)
	checkError(t, err, nil)
	if next.Generation != owner.Generation+1 || next.ID == owner.ID {
		t.Fatalf("new node did not get a new generation: %+v", next)
	}
	checkError(t, session.ReleaseAfterFence(ctx, db, fence, corePub, sig), nil)
	replayed, err := submit(winner.req)
	checkError(t, err, nil)
	if replayed.State != "released" {
		t.Fatalf("old proof revived released owner: %+v", replayed)
	}
	newReplay, err := submit(otherNode)
	checkError(t, err, nil)
	if newReplay != next {
		t.Fatalf("old fence affected new owner: %+v", newReplay)
	}
	_, err = db.ExecContext(ctx, `UPDATE elx_entitlements SET valid_until=clock_timestamp() WHERE id=$1`, entitlement)
	checkError(t, err, nil)
	_, err = submit(winner.req)
	checkError(t, err, session.ErrDenied)
}
