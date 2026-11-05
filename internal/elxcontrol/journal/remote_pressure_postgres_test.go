package journal

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/ElXnet/ElX-control/internal/elxcontrol/accounting"
	"github.com/google/uuid"
)

func remotePressureProof(signer ed25519.PrivateKey, sub, nonce string,
	boot uuid.UUID, sequence, revision, upRate, downRate,
	upPayload, downPayload, upWaits, downWaits uint64, timestamp time.Time) []byte {
	data := make([]byte, 120)
	copy(data[:16], boot[:])
	fields := [13]uint64{
		sequence, uint64(timestamp.UnixNano()), revision, upRate, downRate,
		upPayload, upWaits, 5000000, 1,
		downPayload, downWaits, 8000000, 2,
	}
	for i, value := range fields {
		binary.BigEndian.PutUint64(data[16+i*8:24+i*8], value)
	}
	transcript := fmt.Appendf(nil, "elx-pressure-v1\n%x\n%x\n%x", nonce, sub, data)
	return append(data, ed25519.Sign(signer, transcript)...)
}

func remoteLeaseProof(signer ed25519.PrivateKey, sub, nonce string,
	boot, node uuid.UUID, sequence, revision, up, down uint64,
	expires time.Time) []byte {
	data := make([]byte, 88)
	copy(data[:16], boot[:])
	copy(data[16:32], node[:])
	fields := [7]uint64{
		sequence, uint64(expires.Unix()), up, down,
		revision, up, down,
	}
	for i, value := range fields {
		binary.BigEndian.PutUint64(data[32+i*8:40+i*8], value)
	}
	transcript := fmt.Appendf(nil, "elx-lease-accept-v1\n%x\n%x\n%x", nonce, sub, data)
	return append(data, ed25519.Sign(signer, transcript)...)
}

func TestRemotePressureIsPinnedAndAtomicWithFUPAccounting(t *testing.T) {
	ctx, db := testDatabase(t)
	now := time.Now().UTC()
	entitlement, schedule, period, resource := uuid.New(), uuid.New(), uuid.New(), uuid.New()
	b := accounting.RemoteBinding{
		NodeID: uuid.New(), ExecutorID: uuid.New(), Incarnation: uuid.New(),
		AccountingID: uuid.New(), Generation: 1, ScheduleID: schedule,
	}
	public, signer, err := ed25519.GenerateKey(rand.Reader)
	checkError(t, err, nil)
	sub := "pressure-lab"
	_, err = db.ExecContext(ctx, `INSERT INTO elx_entitlements(id,active_slots,valid_until)
		VALUES($1,2,clock_timestamp()+interval '2 days')`, entitlement)
	checkError(t, err, nil)
	_, err = db.ExecContext(ctx, `INSERT INTO elx_rate_budgets VALUES($1,100,100)`, entitlement)
	checkError(t, err, nil)
	_, err = db.ExecContext(ctx, `INSERT INTO elx_usage_periods
		(id,entitlement_id,starts_at,ends_at,direction,threshold_bytes,reduced_up,reduced_down)
		VALUES($1,$2,$3,$4,'total',1000000,20,20)`,
		period, entitlement, now.Add(-time.Hour), now.Add(time.Hour))
	checkError(t, err, nil)
	_, err = db.ExecContext(ctx, `INSERT INTO elx_period_schedules
		(id,entitlement_id,cadence,timezone_name,current_period_id)
		VALUES($1,$2,'day','UTC',$3)`, schedule, entitlement, period)
	checkError(t, err, nil)
	_, err = db.ExecContext(ctx, `UPDATE elx_usage_periods SET schedule_id=$2 WHERE id=$1`, period, schedule)
	checkError(t, err, nil)
	_, err = db.ExecContext(ctx, `INSERT INTO elx_operation_targets(node_id,resource_id)
		VALUES($1,$2)`, b.NodeID, resource)
	checkError(t, err, nil)
	_, err = db.ExecContext(ctx, `INSERT INTO elx_core_identities
		(node_id,incarnation,public_key) VALUES($1,$2,$3)`,
		b.NodeID, b.Incarnation, []byte(public))
	checkError(t, err, nil)
	_, err = db.ExecContext(ctx, `INSERT INTO elx_rate_grants
		(entitlement_id,node_id,resource_id,committed_up,committed_down,epoch,barrier_public_key)
		VALUES($1,$2,$3,30,70,1,$4)`, entitlement, b.NodeID, resource, []byte(public))
	checkError(t, err, nil)
	_, err = db.ExecContext(ctx, `INSERT INTO elx_accounting_streams
		(node_id,executor_id,incarnation,accounting_id,generation,period_id,primed)
		VALUES($1,$2,$3,$4,1,$5,false)`,
		b.NodeID, b.ExecutorID, b.Incarnation, b.AccountingID, period)
	checkError(t, err, nil)
	_, err = db.ExecContext(ctx, `INSERT INTO elx_accounting_assignments
		(node_id,executor_id,incarnation,accounting_id,generation,period_id,subscription_id,resource_id)
		VALUES($1,$2,$3,$4,1,$5,$6,$7)`,
		b.NodeID, b.ExecutorID, b.Incarnation, b.AccountingID, period, sub, resource)
	checkError(t, err, nil)
	challenge, err := accounting.IssueRemoteChallenge(ctx, db, b.NodeID, b)
	checkError(t, err, nil)
	at := time.Now().UTC().Add(-7 * time.Second)
	usage := remoteUsageProof(t, signer, sub, challenge.Nonce, b.Incarnation, 1, 100, 200, at)
	pressure := remotePressureProof(signer, sub, challenge.Nonce, b.Incarnation,
		2, 1, 30, 70, 100, 200, 3, 5, at.Add(time.Millisecond))
	// Tampered pressure invalidates the entire transaction, including FUP.
	tampered := append([]byte(nil), pressure...)
	tampered[64] ^= 1
	_, err = accounting.SubmitRemoteTelemetry(ctx, db, b.NodeID, b, usage, tampered)
	checkError(t, err, accounting.ErrRemoteEvidence)
	var streamSequence int64
	checkError(t, db.QueryRowContext(ctx, `SELECT sequence FROM elx_accounting_streams
		WHERE node_id=$1 AND accounting_id=$2`, b.NodeID, b.AccountingID).Scan(&streamSequence), nil)
	if streamSequence != 0 {
		t.Fatalf("invalid pressure proof charged usage: %d", streamSequence)
	}
	lease := remoteLeaseProof(signer, sub, challenge.Nonce, b.Incarnation,
		b.NodeID, 10, 1, 30, 70, time.Now().Add(15*time.Second))
	badLease := append([]byte(nil), lease...)
	badLease[20] ^= 1
	_, err = accounting.SubmitRemoteTelemetryWithLease(ctx, db, b.NodeID, b,
		usage, pressure, badLease)
	checkError(t, err, accounting.ErrRemoteEvidence)
	receipt, err := accounting.SubmitRemoteTelemetryWithLease(ctx, db, b.NodeID, b,
		usage, pressure, lease)
	checkError(t, err, nil)
	if receipt.Sequence != 1 {
		t.Fatalf("usage was not durably received: %+v", receipt)
	}
	var storedSeq, up, down, upWaits int64
	checkError(t, db.QueryRowContext(ctx, `SELECT sequence,policy_up,policy_down,up_blocked_calls
		FROM elx_rate_pressure_samples WHERE node_id=$1 AND resource_id=$2`,
		b.NodeID, resource).Scan(&storedSeq, &up, &down, &upWaits), nil)
	if storedSeq != 2 || up != 30 || down != 70 || upWaits != 3 {
		t.Fatalf("verified pressure not committed: seq=%d rate=%d/%d waits=%d", storedSeq, up, down, upWaits)
	}
	_, err = accounting.SubmitRemoteTelemetry(ctx, db, b.NodeID, b, usage, pressure)
	checkError(t, err, accounting.ErrRemoteChallenge)

	challenge, err = accounting.IssueRemoteChallenge(ctx, db, b.NodeID, b)
	checkError(t, err, nil)
	at = time.Now().UTC().Add(-time.Second)
	nextUsage := remoteUsageProof(t, signer, sub, challenge.Nonce, b.Incarnation, 3, 120, 220, at)
	nextPressure := remotePressureProof(signer, sub, challenge.Nonce, b.Incarnation,
		4, 1, 30, 70, 120, 220, 4, 6, at.Add(time.Millisecond))
	nextLease := remoteLeaseProof(signer, sub, challenge.Nonce, b.Incarnation,
		b.NodeID, 11, 1, 30, 70, time.Now().Add(15*time.Second))
	receipt, err = accounting.SubmitRemoteTelemetryWithLease(ctx, db, b.NodeID, b,
		nextUsage, nextPressure, nextLease)
	checkError(t, err, nil)
	if receipt.Sequence != 3 {
		t.Fatalf("expected new usage high watermark: %+v", receipt)
	}
	var countedUp, countedDown int64
	checkError(t, db.QueryRowContext(ctx, `SELECT up_bytes,down_bytes
		FROM elx_usage_periods WHERE id=$1`, period).Scan(&countedUp, &countedDown), nil)
	if countedUp != 20 || countedDown != 20 {
		t.Fatalf("signed usage lost or double counted: %d/%d", countedUp, countedDown)
	}
	// Two separate signed, pinned samples at the same policy revision are
	// necessary for a demand estimate, but a current signed core lease
	// acceptance bound to the same latest sequence is ALSO mandatory.
	preview, err := PreviewDemand(ctx, db, entitlement.String())
	checkError(t, err, nil)
	var leasePressureSeq, leaseSeq int64
	checkError(t, db.QueryRowContext(ctx, `SELECT pressure_sequence,lease_sequence
		FROM elx_rate_lease_acceptances WHERE node_id=$1 AND resource_id=$2`,
		b.NodeID, resource).Scan(&leasePressureSeq, &leaseSeq), nil)
	if leasePressureSeq != 4 || leaseSeq != 11 {
		t.Fatalf("lease proof not tied to latest signed pressure: %d/%d", leasePressureSeq, leaseSeq)
	}
	if len(preview) != 1 || preview[0].Target != (Target{
		NodeID:b.NodeID.String(), ResourceID:resource.String(),
	}) || preview[0].Requested != (Rate{Up:60, Down:100}) {
		t.Fatalf("signed pressure did not produce bounded preview: %+v", preview)
	}

	challenge, err = accounting.IssueRemoteChallenge(ctx, db, b.NodeID, b)
	checkError(t, err, nil)
	at = time.Now().UTC()
	replayedUsage := remoteUsageProof(t, signer, sub, challenge.Nonce, b.Incarnation, 5, 140, 240, at)
	regressedPressure := remotePressureProof(signer, sub, challenge.Nonce, b.Incarnation,
		6, 1, 30, 70, 80, 240, 5, 7, at.Add(time.Millisecond))
	_, err = accounting.SubmitRemoteTelemetry(ctx, db, b.NodeID, b, replayedUsage, regressedPressure)
	if !errors.Is(err, accounting.ErrRemoteEvidence) {
		t.Fatalf("regressed pressure accepted: %v", err)
	}
	checkError(t, db.QueryRowContext(ctx, `SELECT up_bytes,down_bytes
		FROM elx_usage_periods WHERE id=$1`, period).Scan(&countedUp, &countedDown), nil)
	if countedUp != 20 || countedDown != 20 {
		t.Fatalf("failed pressure transaction changed FUP usage: %d/%d", countedUp, countedDown)
	}
	// A core that is no longer the rate-grant signing authority can
	// continue reporting signed billable bytes while reconciliation runs,
	// but its pressure cannot authorize a new speed allocation.
	replacementKey, _, err := ed25519.GenerateKey(rand.Reader)
	checkError(t, err, nil)
	_, err = db.ExecContext(ctx, `UPDATE elx_rate_grants
		SET barrier_public_key=$3 WHERE node_id=$1 AND resource_id=$2`,
		b.NodeID, resource, []byte(replacementKey))
	checkError(t, err, nil)
	validAfterRekey := remotePressureProof(signer, sub, challenge.Nonce, b.Incarnation,
		6, 1, 30, 70, 140, 240, 5, 7, at.Add(time.Millisecond))
	receipt, err = accounting.SubmitRemoteTelemetry(ctx, db, b.NodeID, b,
		replayedUsage, validAfterRekey)
	checkError(t, err, nil)
	if receipt.Sequence != 5 {
		t.Fatalf("billable usage failed during rate core rekey: %+v", receipt)
	}
	checkError(t, db.QueryRowContext(ctx, `SELECT sequence FROM elx_rate_pressure_samples
		WHERE node_id=$1 AND resource_id=$2`, b.NodeID, resource).Scan(&storedSeq), nil)
	if storedSeq != 4 {
		t.Fatalf("retired rate signer updated active pressure stream: %d", storedSeq)
	}
	preview, err = PreviewDemand(ctx, db, entitlement.String())
	checkError(t, err, nil)
	if len(preview) != 0 {
		t.Fatalf("former rate signing key still produced demand: %+v", preview)
	}
	// A pending rate move prevents the old telemetry from authorizing a
	// fresh rate allocation, without forging an applied core acknowledgment.
	_, err = db.ExecContext(ctx, `UPDATE elx_rate_grants
		SET barrier_public_key=$3 WHERE node_id=$1 AND resource_id=$2`,
		b.NodeID, resource, []byte(public))
	checkError(t, err, nil)
	pendingOperation := uuid.NewString()
	_, err = QueueRateMove(ctx, db, entitlement.String(),
		Target{NodeID:b.NodeID.String(),ResourceID:resource.String()},
		pendingOperation, 0, Rate{Up:20,Down:60})
	checkError(t, err, nil)
	preview, err = PreviewDemand(ctx, db, entitlement.String())
	checkError(t, err, nil)
	if len(preview) != 0 {
		t.Fatalf("old evidence survived a pending policy transition: %+v", preview)
	}
}
