package journal

import (
	"testing"

	"github.com/google/uuid"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/session"
)

func TestLegacySessionWithoutAuthenticatedProfileCannotBeQueued(t *testing.T) {
	ctx,db:=testDatabase(t)
	entitlement,device,owner:=uuid.New(),uuid.New(),uuid.New()
	_,err:=db.ExecContext(ctx,`INSERT INTO elx_entitlements(id,active_slots,valid_until)
		VALUES($1,2,clock_timestamp()+interval '1 day')`,entitlement)
	checkError(t,err,nil)
	_,err=db.ExecContext(ctx,`INSERT INTO elx_devices(id,entitlement_id,key_generation)
		VALUES($1,$2,1)`,device,entitlement)
	checkError(t,err,nil)
	_,err=db.ExecContext(ctx,`INSERT INTO elx_session_owners
		(id,entitlement_id,device_id,node_id,operation_id,generation,key_generation,
		proof_hash,state,core_incarnation)
		VALUES($1,$2,$3,$4,$5,1,1,$6,'active',$7)`,
		owner,entitlement,device,uuid.New(),uuid.New(),make([]byte,32),uuid.New())
	checkError(t,err,nil)

	checkError(t,session.QueueDrain(ctx,db,owner),session.ErrDrain)
	var state string
	err=db.QueryRowContext(ctx,`SELECT state FROM elx_session_owners WHERE id=$1`,owner).Scan(&state)
	checkError(t,err,nil)
	if state!="active" {t.Fatalf("legacy owner changed state without VLESS profile: %s",state)}

	// A trusted migration may backfill a profile ONLY after verifying it
	// belongs to the original authenticated VLESS account.
	_,err=db.ExecContext(ctx,`UPDATE elx_session_owners SET profile_id=$2 WHERE id=$1`,owner,uuid.New())
	checkError(t,err,nil)
	checkError(t,session.QueueDrain(ctx,db,owner),nil)
	checkError(t,session.QueueDrain(ctx,db,owner),nil)
	err=db.QueryRowContext(ctx,`SELECT state FROM elx_session_owners WHERE id=$1`,owner).Scan(&state)
	checkError(t,err,nil)
	if state!="draining" {t.Fatalf("queued drain did not retain occupied slot: %s",state)}
}
