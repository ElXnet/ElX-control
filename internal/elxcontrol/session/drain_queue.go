package session

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"
)

var ErrDrain = errors.New("session is not eligible for an authorized drain")

// QueueDrain is a trusted Control command (e.g. from an authenticated LK
// disable operation after account ownership checks). It never frees a slot.
// Only a subsequent core-signed, generation- and profile-bound proof can
// release ownership. Replays are idempotent for a draining/released owner.
func QueueDrain(ctx context.Context, db *sql.DB, ownerID uuid.UUID) error {
	if db==nil || ownerID==uuid.Nil {return ErrDrain}
	tx,err:=db.BeginTx(ctx,&sql.TxOptions{Isolation:sql.LevelReadCommitted})
	if err!=nil {return err}
	defer tx.Rollback()
	// All session writers lock entitlement before owner rows.
	var entitlement uuid.UUID
	err=tx.QueryRowContext(ctx,`SELECT e.id FROM elx_entitlements e
		JOIN elx_session_owners o ON o.entitlement_id=e.id
		WHERE o.id=$1 FOR UPDATE OF e`,ownerID).Scan(&entitlement)
	if errors.Is(err,sql.ErrNoRows) {return ErrDrain}
	if err!=nil{return err}
	var state string
	var profile,incarnation uuid.NullUUID
	err=tx.QueryRowContext(ctx,`SELECT state,profile_id,core_incarnation
		FROM elx_session_owners WHERE id=$1 FOR UPDATE`,ownerID).
		Scan(&state,&profile,&incarnation)
	if errors.Is(err,sql.ErrNoRows){return ErrDrain}
	if err!=nil{return err}
	if state=="released" || state=="draining" {return tx.Commit()}
	if state!="reserving" && state!="active" && state!="unknown" ||
		!profile.Valid || profile.UUID==uuid.Nil || !incarnation.Valid || incarnation.UUID==uuid.Nil {
		return ErrDrain
	}
	_,err=tx.ExecContext(ctx,`UPDATE elx_session_owners
		SET state='draining' WHERE id=$1 AND state=$2`,ownerID,state)
	if err!=nil{return err}
	return tx.Commit()
}
