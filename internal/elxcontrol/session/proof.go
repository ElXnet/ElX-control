package session

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/binary"
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrProof         = errors.New("device proof rejected")
	ErrChallengeBusy = errors.New("device already has an outstanding challenge")
)

// Admission binds a reservation to one node, core boot, profile and channel.
// The caller must derive NodeID from mTLS and the hashes from the actual flow.
// Client-supplied values for those fields do not prove possession on a VPN flow.
type Admission struct {
	EntitlementID uuid.UUID
	DeviceID      uuid.UUID
	NodeID        uuid.UUID
	OperationID   uuid.UUID
	KeyGeneration int64
	Incarnation   uuid.UUID
	ProfileID     uuid.UUID
	HandshakeHash [32]byte
	FlowBinding   [32]byte
}

type Challenge struct {
	Nonce     [32]byte
	ExpiresAt time.Time
}

func (a Admission) valid() bool {
	return a.EntitlementID != uuid.Nil && a.DeviceID != uuid.Nil &&
		a.NodeID != uuid.Nil && a.OperationID != uuid.Nil && a.KeyGeneration > 0 &&
		a.Incarnation != uuid.Nil && a.ProfileID != uuid.Nil &&
		a.HandshakeHash != [32]byte{} && a.FlowBinding != [32]byte{}
}

// ProofTranscript is the exact message signed by an Ed25519 device key.
// All UUIDs are RFC 9562 octets. The generation is an unsigned big-endian
// 64-bit number, followed by the two 32-byte channel hashes.
func ProofTranscript(a Admission, nonce [32]byte) []byte {
	out := []byte("elx-device-reserve-v1\x00")
	out = append(out, nonce[:]...)
	for _, id := range [6]uuid.UUID{a.EntitlementID, a.DeviceID, a.NodeID, a.OperationID, a.Incarnation, a.ProfileID} {
		out = append(out, id[:]...)
	}
	out = binary.BigEndian.AppendUint64(out, uint64(a.KeyGeneration))
	out = append(out, a.HandshakeHash[:]...)
	return append(out, a.FlowBinding[:]...)
}

func (a Admission) reservation() reservationRequest {
	return reservationRequest{EntitlementID: a.EntitlementID, DeviceID: a.DeviceID, NodeID: a.NodeID,
		OperationID: a.OperationID, KeyGeneration: a.KeyGeneration, Incarnation: a.Incarnation}
}

// IssueChallenge keeps at most one outstanding challenge per enrolled device.
// Retrying the same intent returns the same nonce until it expires.
func IssueChallenge(ctx context.Context, db *sql.DB, a Admission) (Challenge, error) {
	if !a.valid() {
		return Challenge{}, ErrInvalid
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return Challenge{}, err
	}
	defer tx.Rollback()
	if _, err := lockEligibleDevice(ctx, tx, a.reservation()); err != nil {
		return Challenge{}, err
	}
	if _, err := devicePublicKey(ctx, tx, a.DeviceID); err != nil {
		return Challenge{}, err
	}
	intent := sha256.Sum256(ProofTranscript(a, [32]byte{}))
	var existingNonce, existingIntent []byte
	var expires time.Time
	err = tx.QueryRowContext(ctx, `SELECT nonce,intent_hash,expires_at FROM elx_device_challenges
		WHERE device_id=$1 AND expires_at>clock_timestamp()`, a.DeviceID).Scan(&existingNonce, &existingIntent, &expires)
	var result Challenge
	if err == nil {
		if !sameDigest(existingIntent, intent) {
			return Challenge{}, ErrChallengeBusy
		}
		copy(result.Nonce[:], existingNonce)
		result.ExpiresAt = expires
	} else {
		if !errors.Is(err, sql.ErrNoRows) {
			return Challenge{}, err
		}
		if _, err := rand.Read(result.Nonce[:]); err != nil {
			return Challenge{}, err
		}
		err = tx.QueryRowContext(ctx, `INSERT INTO elx_device_challenges(device_id,nonce,intent_hash,expires_at)
			VALUES ($1,$2,$3,clock_timestamp()+interval '30 seconds')
			ON CONFLICT(device_id) DO UPDATE SET nonce=excluded.nonce,intent_hash=excluded.intent_hash,expires_at=excluded.expires_at
			RETURNING expires_at`, a.DeviceID, result.Nonce[:], intent[:]).Scan(&result.ExpiresAt)
		if err != nil {
			return Challenge{}, err
		}
	}
	if err := tx.Commit(); err != nil {
		return Challenge{}, err
	}
	return result, nil
}

// ReserveWithProof verifies possession and consumes the challenge in the same
// transaction as the new reservation. A successful replay returns only the
// previous owner and cannot consume a different challenge.
func ReserveWithProof(ctx context.Context, db *sql.DB, a Admission, nonce [32]byte, signature []byte) (Owner, error) {
	if !a.valid() || nonce == [32]byte{} || len(signature) != ed25519.SignatureSize {
		return Owner{}, ErrInvalid
	}
	transcript := ProofTranscript(a, nonce)
	intent := sha256.Sum256(ProofTranscript(a, [32]byte{}))
	req := a.reservation()
	req.ProofHash = sha256.Sum256(transcript)
	return reserve(ctx, db, req, func(ctx context.Context, tx *sql.Tx, replay bool) error {
		key, err := devicePublicKey(ctx, tx, a.DeviceID)
		if err != nil {
			return err
		}
		if !ed25519.Verify(key, transcript, signature) {
			return ErrProof
		}
		if replay {
			return nil
		}
		result, err := tx.ExecContext(ctx, `DELETE FROM elx_device_challenges
			WHERE device_id=$1 AND nonce=$2 AND intent_hash=$3 AND expires_at>clock_timestamp()`, a.DeviceID, nonce[:], intent[:])
		if err != nil {
			return err
		}
		rows, err := result.RowsAffected()
		if err != nil {
			return err
		}
		if rows != 1 {
			return ErrProof
		}
		return nil
	})
}

func sameDigest(value []byte, digest [32]byte) bool {
	return len(value) == 32 && [32]byte(value) == digest
}

func devicePublicKey(ctx context.Context, tx *sql.Tx, id uuid.UUID) (ed25519.PublicKey, error) {
	var key []byte
	err := tx.QueryRowContext(ctx, `SELECT public_key FROM elx_devices WHERE id=$1`, id).Scan(&key)
	if err != nil {
		return nil, err
	}
	if len(key) != ed25519.PublicKeySize {
		return nil, ErrProof
	}
	return ed25519.PublicKey(key), nil
}
