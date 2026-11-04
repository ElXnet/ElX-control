package management

import (
	"context"
	"database/sql"
	"errors"

	"github.com/ElXnet/ElX-control/internal/elxcontrol/journal"
)

// RevokeResult never claims a session has been released: every occupied
// session stays charged until a signed ElXray fence is recorded.
type RevokeResult struct {
	DeviceID string `json:"deviceId"`
	Revoked bool `json:"revoked"`
	AlreadyRevoked bool `json:"alreadyRevoked"`
	DrainQueued int `json:"drainQueued"`
	Undrainable int `json:"undrainable"`
}

// RevokeDevice denies future admission and queues profile-bound drains in one
// transaction. Rows without a trusted profile/boot remain occupied and require
// operator recovery. Lock order agrees with session admission: entitlement,
// device, session owners. No caller supplies core keys or release proofs.
func (s SQLStore) RevokeDevice(ctx context.Context, entitlement, device string) (RevokeResult, error) {
	out := RevokeResult{DeviceID: device}
	if s.DB == nil || !canonical(entitlement) || !canonical(device) {
		return out, journal.ErrInvalid
	}
	tx, err := s.DB.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil { return out, err }
	defer tx.Rollback()
	var existing string
	err = tx.QueryRowContext(ctx, "SELECT id::text FROM elx_entitlements WHERE id=$1 FOR UPDATE", entitlement).Scan(&existing)
	if errors.Is(err,sql.ErrNoRows){return out,ErrNotFound}
	if err!=nil{return out,err}
	var previouslyRevoked bool
	err=tx.QueryRowContext(ctx,"SELECT revoked FROM elx_devices WHERE id=$1 AND entitlement_id=$2 FOR UPDATE",device,entitlement).Scan(&previouslyRevoked)
	if errors.Is(err,sql.ErrNoRows){return out,ErrNotFound}
	if err!=nil{return out,err}
	rows,err:=tx.QueryContext(ctx,`SELECT state,profile_id IS NOT NULL AND core_incarnation IS NOT NULL
		FROM elx_session_owners WHERE entitlement_id=$1 AND device_id=$2
		AND state<>'released' ORDER BY id FOR UPDATE`,entitlement,device)
	if err!=nil{return out,err}
	type owner struct{state string;bound bool}
	owners:=[]owner{}
	for rows.Next(){
		var o owner
		if err=rows.Scan(&o.state,&o.bound);err!=nil{rows.Close();return out,err}
		owners=append(owners,o)
		if len(owners)>1000{rows.Close();return out,journal.ErrInvalid}
	}
	err=rows.Err()
	rows.Close()
	if err!=nil{return out,err}
	for _,o:=range owners{
		if o.state=="draining" {
			out.DrainQueued++
		} else if o.bound && (o.state=="reserving"||o.state=="active"||o.state=="unknown") {
			out.DrainQueued++
		} else {
			out.Undrainable++
		}
	}
	// For already-draining entries nothing changes. New drains must retain
	// their current profile, incarnation and generation.
	_,err=tx.ExecContext(ctx,`UPDATE elx_session_owners SET state='draining'
		WHERE entitlement_id=$1 AND device_id=$2 AND state IN ('reserving','active','unknown')
		AND profile_id IS NOT NULL AND core_incarnation IS NOT NULL`,entitlement,device)
	if err!=nil{return out,err}
	_,err=tx.ExecContext(ctx,"UPDATE elx_devices SET revoked=true WHERE id=$1 AND entitlement_id=$2",device,entitlement)
	if err!=nil{return out,err}
	if err=tx.Commit();err!=nil{return out,err}
	out.Revoked=true
	out.AlreadyRevoked=previouslyRevoked
	return out,nil
}
