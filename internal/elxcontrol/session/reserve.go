// Package session tracks durable ownership of subscription session slots.
package session

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrInvalid  = errors.New("invalid session reservation")
	ErrDenied   = errors.New("entitlement or device unavailable")
	ErrFull     = errors.New("no active session slots available")
	ErrOwned    = errors.New("device already has a session owner")
	ErrConflict = errors.New("reservation operation reused with different input")
)

type reservationRequest struct {
	EntitlementID uuid.UUID
	DeviceID      uuid.UUID
	NodeID        uuid.UUID
	OperationID   uuid.UUID
	Incarnation   uuid.UUID
	KeyGeneration int64
	ProofHash     [32]byte
	ProfileID     uuid.UUID
}

type Owner struct {
	ID         uuid.UUID
	Generation int64
	State      string
}

type verifyReservation func(context.Context, *sql.Tx, bool) error

func reserve(ctx context.Context, db *sql.DB, req reservationRequest, verify verifyReservation) (Owner, error) {
	if req.EntitlementID == uuid.Nil || req.DeviceID == uuid.Nil || req.NodeID == uuid.Nil ||
		req.OperationID == uuid.Nil || req.Incarnation == uuid.Nil || req.KeyGeneration <= 0 || req.ProfileID == uuid.Nil || req.ProofHash == [32]byte{} {
		return Owner{}, ErrInvalid
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return Owner{}, err
	}
	defer tx.Rollback()
	limit, err := lockEligibleDevice(ctx, tx, req)
	if err != nil {
		return Owner{}, err
	}

	var owner Owner
	var device, node uuid.UUID
	var priorProfile uuid.NullUUID
	var priorKey int64
	var proof []byte
	err = tx.QueryRowContext(ctx, `SELECT id,generation,state,device_id,node_id,key_generation,proof_hash,profile_id
		FROM elx_session_owners WHERE entitlement_id=$1 AND operation_id=$2`, req.EntitlementID, req.OperationID).
		Scan(&owner.ID, &owner.Generation, &owner.State, &device, &node, &priorKey, &proof, &priorProfile)
	if err == nil {
		if device != req.DeviceID || node != req.NodeID || priorKey != req.KeyGeneration || !priorProfile.Valid || priorProfile.UUID != req.ProfileID || !bytes.Equal(proof, req.ProofHash[:]) {
			return Owner{}, ErrConflict
		}
		if err := verify(ctx, tx, true); err != nil {
			return Owner{}, err
		}
		if err := tx.Commit(); err != nil {
			return Owner{}, err
		}
		return owner, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		return Owner{}, err
	}
	if err := verify(ctx, tx, false); err != nil {
		return Owner{}, err
	}

	var occupied int
	var deviceOwned bool
	err = tx.QueryRowContext(ctx, `SELECT count(*), COALESCE(bool_or(device_id=$2),false)
		FROM elx_session_owners WHERE entitlement_id=$1 AND state <> 'released'`, req.EntitlementID, req.DeviceID).
		Scan(&occupied, &deviceOwned)
	if err != nil {
		return Owner{}, err
	}
	if deviceOwned {
		return Owner{}, ErrOwned
	}
	if occupied >= limit {
		return Owner{}, ErrFull
	}

	owner.ID, err = uuid.NewRandom()
	if err != nil {
		return Owner{}, err
	}
	err = tx.QueryRowContext(ctx, `INSERT INTO elx_session_owners
		(id,entitlement_id,device_id,node_id,operation_id,generation,key_generation,proof_hash,state,core_incarnation,profile_id)
		VALUES ($1,$2,$3,$4,$5,(SELECT COALESCE(max(generation),0)+1 FROM elx_session_owners WHERE device_id=$3),
		$6,$7,'reserving',$8,$9) RETURNING generation,state`, owner.ID, req.EntitlementID, req.DeviceID, req.NodeID,
		req.OperationID, req.KeyGeneration, req.ProofHash[:], req.Incarnation, req.ProfileID).Scan(&owner.Generation, &owner.State)
	if err != nil {
		return Owner{}, err
	}
	if err := tx.Commit(); err != nil {
		return Owner{}, err
	}
	return owner, nil
}

// Lock order is entitlement then device for all admission mutations.
func lockEligibleDevice(ctx context.Context, tx *sql.Tx, req reservationRequest) (int, error) {
	var err error
	var limit int
	var enabled bool
	var validUntil time.Time
	err = tx.QueryRowContext(ctx, `SELECT active_slots, enabled, valid_until
		FROM elx_entitlements WHERE id=$1 FOR UPDATE`, req.EntitlementID).Scan(&limit, &enabled, &validUntil)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrDenied
	}
	if err != nil {
		return 0, err
	}

	var keyGeneration int64
	var revoked bool
	err = tx.QueryRowContext(ctx, `SELECT key_generation, revoked FROM elx_devices
		WHERE entitlement_id=$1 AND id=$2 FOR UPDATE`, req.EntitlementID, req.DeviceID).Scan(&keyGeneration, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return 0, ErrDenied
	}
	if err != nil {
		return 0, err
	}
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return 0, err
	}
	if !enabled || !validUntil.After(now) || revoked || keyGeneration != req.KeyGeneration {
		return 0, ErrDenied
	}

	return limit, nil
}
