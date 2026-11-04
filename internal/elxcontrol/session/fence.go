package session

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/binary"
	"errors"

	"github.com/google/uuid"
)

var ErrFence = errors.New("session fence receipt rejected")

// Fence identifies the session generation and original core boot that
// owned it. A core may sign this only after durable denial and flow drain.
type Fence struct {
	OwnerID     uuid.UUID
	Generation  int64
	NodeID      uuid.UUID
	Incarnation uuid.UUID
}

func FenceTranscript(f Fence) []byte {
	out := []byte("elx-session-fence-v1\x00")
	out = append(out, f.OwnerID[:]...)
	out = binary.BigEndian.AppendUint64(out, uint64(f.Generation))
	out = append(out, f.NodeID[:]...)
	return append(out, f.Incarnation[:]...)
}

// ReleaseAfterFence frees a slot only for the generation named in a signed
// fence receipt. The caller supplies the registered core key for the
// authenticated node and incarnation, never a key from the receipt.
func ReleaseAfterFence(ctx context.Context, db *sql.DB, f Fence, coreKey ed25519.PublicKey, signature []byte) error {
	if f.OwnerID == uuid.Nil || f.Generation <= 0 || f.NodeID == uuid.Nil ||
		f.Incarnation == uuid.Nil || len(coreKey) != ed25519.PublicKeySize ||
		!ed25519.Verify(coreKey, FenceTranscript(f), signature) {
		return ErrFence
	}

	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return err
	}
	defer tx.Rollback()

	// Serialize release with admission even when the device has since been revoked.
	var entitlement uuid.UUID
	err = tx.QueryRowContext(ctx, `SELECT e.id FROM elx_entitlements e
		JOIN elx_session_owners o ON o.entitlement_id=e.id
		WHERE o.id=$1 FOR UPDATE OF e`, f.OwnerID).Scan(&entitlement)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrFence
	}
	if err != nil {
		return err
	}
	// The claimed key is not authority: resolve the pinned identity for this
	// node and exact core boot from Control's durable registry. Never trust a
	// key delivered in the fence payload or supplied by an untrusted caller.
	var pinned []byte
	var revoked bool
	err = tx.QueryRowContext(ctx, `SELECT public_key,revoked FROM elx_core_identities
		WHERE node_id=$1 AND incarnation=$2 FOR UPDATE`, f.NodeID, f.Incarnation).Scan(&pinned, &revoked)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrFence
	}
	if err != nil {
		return err
	}
	if revoked || !bytes.Equal(pinned, coreKey) {
		return ErrFence
	}
	var state string
	var prior []byte
	err = tx.QueryRowContext(ctx, `SELECT state,fence_signature FROM elx_session_owners
		WHERE id=$1 AND generation=$2 AND node_id=$3 AND core_incarnation=$4`,
		f.OwnerID, f.Generation, f.NodeID, f.Incarnation).Scan(&state, &prior)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrFence
	}
	if err != nil {
		return err
	}
	if state == "released" {
		if !bytes.Equal(prior, signature) {
			return ErrFence
		}
		return tx.Commit()
	}
	_, err = tx.ExecContext(ctx, `UPDATE elx_session_owners SET state='released',fence_signature=$2 WHERE id=$1`,
		f.OwnerID, signature)
	if err != nil {
		return err
	}
	return tx.Commit()
}
