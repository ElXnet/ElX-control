package journal

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/accounting"
)

func remoteUsageProof(t *testing.T, signer ed25519.PrivateKey, sub, nonce string,
	incarnation uuid.UUID, seq, up, down int64, at time.Time) []byte {
	t.Helper()
	data := append([]byte{}, incarnation[:]...)
	data = binary.BigEndian.AppendUint64(data, uint64(seq))
	data = binary.BigEndian.AppendUint64(data, uint64(at.UnixNano()))
	data = binary.BigEndian.AppendUint64(data, uint64(up))
	data = binary.BigEndian.AppendUint64(data, uint64(down))
	transcript := fmt.Appendf(nil, "elx-usage-v1\n%x\n%x\n%x", nonce, sub, data)
	return append(data, ed25519.Sign(signer, transcript)...)
}

func TestRemoteSignedUsageTwoNodesAuthenticatedAndReplaySafe(t *testing.T) {
	ctx, db := testDatabase(t)
	db.SetMaxOpenConns(12)
	entitlement, schedule, period := uuid.New(), uuid.New(), uuid.New()
	now := time.Now().UTC().Truncate(time.Second)
	start := now.Truncate(24*time.Hour)
	end := start.AddDate(0, 0, 1)
	_, err := db.ExecContext(ctx, `INSERT INTO elx_entitlements(id,active_slots,valid_until)
		VALUES($1,2,clock_timestamp()+interval '2 days')`, entitlement)
	checkError(t, err, nil)
	_, err = db.ExecContext(ctx, `INSERT INTO elx_rate_budgets VALUES($1,100,100)`, entitlement)
	checkError(t, err, nil)
	_, err = db.ExecContext(ctx, `INSERT INTO elx_usage_periods
		(id,entitlement_id,starts_at,ends_at,direction,threshold_bytes,reduced_up,reduced_down)
		VALUES($1,$2,$3,$4,'total',100,20,20)`,
		period, entitlement, start, end)
	checkError(t, err, nil)
	_, err = db.ExecContext(ctx, `INSERT INTO elx_period_schedules
		(id,entitlement_id,cadence,timezone_name,current_period_id)
		VALUES($1,$2,'day','UTC',$3)`, schedule, entitlement, period)
	checkError(t, err, nil)
	_, err = db.ExecContext(ctx, `UPDATE elx_usage_periods SET schedule_id=$2 WHERE id=$1`,
		period, schedule)
	checkError(t, err, nil)
	type source struct {
		binding accounting.RemoteBinding
		sub string
		key ed25519.PrivateKey
	}
	var nodes [2]source
	for i := range nodes {
		binding := accounting.RemoteBinding{
			NodeID:uuid.New(), ExecutorID:uuid.New(), Incarnation:uuid.New(),
			AccountingID:uuid.New(), Generation:1, ScheduleID:schedule,
		}
		pub, key, err := ed25519.GenerateKey(rand.Reader)
		checkError(t, err, nil)
		sub := uuid.NewString()
		_, err = db.ExecContext(ctx, `INSERT INTO elx_core_identities
			(node_id,incarnation,public_key) VALUES($1,$2,$3)`,
			binding.NodeID, binding.Incarnation, []byte(pub))
		checkError(t, err, nil)
		_, err = db.ExecContext(ctx, `INSERT INTO elx_accounting_streams
			(node_id,executor_id,incarnation,accounting_id,generation,period_id)
			VALUES($1,$2,$3,$4,$5,$6)`, binding.NodeID, binding.ExecutorID,
			binding.Incarnation, binding.AccountingID, binding.Generation, period)
		checkError(t, err, nil)
		_, err = db.ExecContext(ctx, `INSERT INTO elx_accounting_assignments
			(node_id,executor_id,incarnation,accounting_id,generation,period_id,subscription_id)
			VALUES($1,$2,$3,$4,$5,$6,$7)`, binding.NodeID, binding.ExecutorID,
			binding.Incarnation, binding.AccountingID, binding.Generation, period, sub)
		checkError(t, err, nil)
		nodes[i]=source{binding,sub,key}
	}

	first, err := accounting.IssueRemoteChallenge(ctx,db,nodes[0].binding.NodeID,nodes[0].binding)
	checkError(t,err,nil)
	if first.Subscription != nodes[0].sub || len(first.Nonce)!=32 || !first.ExpiresAt.After(now) {
		t.Fatalf("incorrect Control challenge %+v", first)
	}
	retry, err := accounting.IssueRemoteChallenge(ctx,db,nodes[0].binding.NodeID,nodes[0].binding)
	checkError(t,err,nil)
	if retry.Nonce!=first.Nonce {t.Fatal("retry issued a second nonce for one pending challenge")}

	one:=remoteUsageProof(t,nodes[0].key,nodes[0].sub,first.Nonce,nodes[0].binding.Incarnation,1,20,30,now)
	_,err=accounting.SubmitRemoteUsage(ctx,db,nodes[1].binding.NodeID,nodes[0].binding,one)
	checkError(t,err,accounting.ErrSample)
	// A tampered counter changes the signed bytes, and must not consume the
	// challenge, leaving the real core free to retry its valid response.
	tampered:=append([]byte{},one...)
	tampered[40]^=1
	_,err=accounting.SubmitRemoteUsage(ctx,db,nodes[0].binding.NodeID,nodes[0].binding,tampered)
	checkError(t,err,accounting.ErrRemoteEvidence)
	r1,err:=accounting.SubmitRemoteUsage(ctx,db,nodes[0].binding.NodeID,nodes[0].binding,one)
	checkError(t,err,nil)
	if r1.Sequence!=1 || r1.Crossed {t.Fatalf("unexpected first accounting receipt %+v",r1)}
	_,err=accounting.SubmitRemoteUsage(ctx,db,nodes[0].binding.NodeID,nodes[0].binding,one)
	checkError(t,err,accounting.ErrRemoteChallenge)

	second,err:=accounting.IssueRemoteChallenge(ctx,db,nodes[1].binding.NodeID,nodes[1].binding)
	checkError(t,err,nil)
	if second.Subscription!=nodes[1].sub {t.Fatalf("node 2 received another subscription: %+v",second)}
	two:=remoteUsageProof(t,nodes[1].key,nodes[1].sub,second.Nonce,nodes[1].binding.Incarnation,1,40,20,now)
	r2,err:=accounting.SubmitRemoteUsage(ctx,db,nodes[1].binding.NodeID,nodes[1].binding,two)
	checkError(t,err,nil)
	if !r2.Crossed {t.Fatal("two nodes exceeded 100-byte FUP without triggering event")}

	var events int
	err=db.QueryRowContext(ctx,`SELECT count(*) FROM elx_fup_events WHERE period_id=$1`,period).Scan(&events)
	checkError(t,err,nil)
	if events!=1 {t.Fatalf("FUP transition duplicated: %d events",events)}

	// Revoking the pinned core identity rejects even correctly signed fresh
	// evidence, and does not consume a challenge from another incarnation.
	third,err:=accounting.IssueRemoteChallenge(ctx,db,nodes[0].binding.NodeID,nodes[0].binding)
	checkError(t,err,nil)
	if third.Nonce==first.Nonce {t.Fatal("consumed nonce was issued again")}
	_,err=db.ExecContext(ctx,`UPDATE elx_core_identities SET revoked=true
		WHERE node_id=$1 AND incarnation=$2`,nodes[0].binding.NodeID,nodes[0].binding.Incarnation)
	checkError(t,err,nil)
	newProof:=remoteUsageProof(t,nodes[0].key,nodes[0].sub,third.Nonce,nodes[0].binding.Incarnation,2,60,40,now)
	_,err=accounting.SubmitRemoteUsage(ctx,db,nodes[0].binding.NodeID,nodes[0].binding,newProof)
	checkError(t,err,accounting.ErrStream)

	// A challenge issued for the old schedule period cannot be consumed
	// after that period is sealed, even with a valid core signature.
	newChallenge,err:=accounting.IssueRemoteChallenge(ctx,db,nodes[1].binding.NodeID,nodes[1].binding)
	checkError(t,err,nil)
	change,err:=AdvancePeriod(ctx,db,schedule,end.Add(time.Second))
	checkError(t,err,nil)
	if !change.Advanced {t.Fatal("missed schedule rollover")}
	oldProof:=remoteUsageProof(t,nodes[1].key,nodes[1].sub,newChallenge.Nonce,nodes[1].binding.Incarnation,2,60,60,now)
	_,err=accounting.SubmitRemoteUsage(ctx,db,nodes[1].binding.NodeID,nodes[1].binding,oldProof)
	if !errors.Is(err,accounting.ErrStream) && !errors.Is(err,accounting.ErrRemoteChallenge) {
		t.Fatalf("accepted stale-period receipt after rollover: %v",err)
	}
}
