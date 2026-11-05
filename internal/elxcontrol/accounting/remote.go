package accounting

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"time"

	"github.com/google/uuid"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/corepolicy"
)

var (
	ErrRemoteChallenge = errors.New("remote usage challenge expired or unavailable")
	ErrRemoteEvidence  = errors.New("untrusted signed usage evidence")
)

// RemoteBinding is a pre-provisioned accounting stream selector. NodeID is
// checked against the node's verified mTLS SPIFFE identity. The period,
// subscription and signing key are ALWAYS resolved from Control's database.
type RemoteBinding struct {
	NodeID       uuid.UUID
	ExecutorID   uuid.UUID
	Incarnation  uuid.UUID
	AccountingID uuid.UUID
	Generation   int64
	ScheduleID   uuid.UUID
}

// Valid validates the local node configuration; the server additionally
// verifies that the node UUID matches its authenticated mTLS certificate.
func (b RemoteBinding) Valid() bool {
	return b.NodeID != uuid.Nil && b.ExecutorID != uuid.Nil &&
		b.Incarnation != uuid.Nil && b.AccountingID != uuid.Nil &&
		b.Generation > 0 && b.ScheduleID != uuid.Nil
}

func (b RemoteBinding) valid(authenticated uuid.UUID) bool {
	return b.Valid() && authenticated == b.NodeID
}

type RemoteChallenge struct {
	Subscription string
	Nonce        string
	ExpiresAt    time.Time
}

func remoteBindingPeriod(ctx context.Context, tx *sql.Tx, b RemoteBinding) (uuid.UUID, time.Time, error) {
	var period uuid.UUID
	var ends time.Time
	err := tx.QueryRowContext(ctx, `SELECT s.current_period_id,p.ends_at
		FROM elx_period_schedules s JOIN elx_usage_periods p ON p.id=s.current_period_id
		WHERE s.id=$1 AND p.starts_at<=clock_timestamp()
		  AND p.ends_at>clock_timestamp() FOR SHARE OF s`, b.ScheduleID).Scan(&period, &ends)
	if errors.Is(err, sql.ErrNoRows) {
		return uuid.Nil, time.Time{}, ErrStream
	}
	return period, ends, err
}

func remoteSubscription(ctx context.Context, tx *sql.Tx, b RemoteBinding, period uuid.UUID) (string, []byte, error) {
	var subscription string
	var key []byte
	err := tx.QueryRowContext(ctx, `SELECT a.subscription_id,c.public_key
		FROM elx_accounting_assignments a
		JOIN elx_core_identities c ON c.node_id=a.node_id AND c.incarnation=a.incarnation
		WHERE a.node_id=$1 AND a.executor_id=$2 AND a.incarnation=$3 AND a.active
		AND a.accounting_id=$4 AND a.generation=$5 AND a.period_id=$6
		AND c.revoked=false FOR SHARE OF a,c`,
		b.NodeID, b.ExecutorID, b.Incarnation, b.AccountingID, b.Generation, period).
		Scan(&subscription, &key)
	if errors.Is(err, sql.ErrNoRows) {
		return "", nil, ErrStream
	}
	if err != nil {
		return "", nil, err
	}
	if len(key) != ed25519.PublicKeySize || subscription == "" {
		return "", nil, ErrStream
	}
	return subscription, key, nil
}

// IssueRemoteChallenge returns a nonce for one specifically assigned stream.
// Repeated attempts while the challenge is valid return the same nonce; after
// expiry or rollover the nonce changes. This survives agent process restarts.
func IssueRemoteChallenge(ctx context.Context, db *sql.DB, authenticatedNode uuid.UUID,
	b RemoteBinding) (RemoteChallenge, error) {
	if db == nil || !b.valid(authenticatedNode) {
		return RemoteChallenge{}, ErrSample
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return RemoteChallenge{}, err
	}
	defer tx.Rollback()
	period, ends, err := remoteBindingPeriod(ctx, tx, b)
	if err != nil {
		return RemoteChallenge{}, err
	}
	subscription, _, err := remoteSubscription(ctx, tx, b, period)
	if err != nil {
		return RemoteChallenge{}, err
	}
	var nonce [16]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return RemoteChallenge{}, err
	}
	out := RemoteChallenge{Subscription: subscription}
	err = tx.QueryRowContext(ctx, `INSERT INTO elx_remote_usage_challenges
		(node_id,executor_id,incarnation,accounting_id,generation,schedule_id,period_id,nonce,expires_at)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8,LEAST(clock_timestamp()+interval '30 seconds',$9))
		ON CONFLICT(node_id,executor_id,incarnation,accounting_id,generation,schedule_id)
		DO UPDATE SET
		  nonce=CASE WHEN elx_remote_usage_challenges.period_id=EXCLUDED.period_id
		    AND elx_remote_usage_challenges.expires_at>clock_timestamp()
		    THEN elx_remote_usage_challenges.nonce ELSE EXCLUDED.nonce END,
		  expires_at=CASE WHEN elx_remote_usage_challenges.period_id=EXCLUDED.period_id
		    AND elx_remote_usage_challenges.expires_at>clock_timestamp()
		    THEN elx_remote_usage_challenges.expires_at ELSE EXCLUDED.expires_at END,
		  period_id=EXCLUDED.period_id
		RETURNING nonce,expires_at`,
		b.NodeID, b.ExecutorID, b.Incarnation, b.AccountingID,
		b.Generation, b.ScheduleID, period, hex.EncodeToString(nonce[:]), ends).
		Scan(&out.Nonce, &out.ExpiresAt)
	if err != nil {
		return RemoteChallenge{}, err
	}
	if err := tx.Commit(); err != nil {
		return RemoteChallenge{}, err
	}
	return out, nil
}

// SubmitRemoteUsage verifies source mTLS, current-period assignment, durable
// pinned core key, challenge uniqueness, and the exact ElXray signature. It
// consumes the challenge in the SAME transaction that advances the FUP
// high-watermark. A lost response is retried with a fresh challenge.
func SubmitRemoteUsage(ctx context.Context, db *sql.DB, authenticatedNode uuid.UUID,
	b RemoteBinding, evidence []byte) (Receipt, error) {
	return submitRemoteTelemetry(ctx, db, authenticatedNode, b, evidence, nil)
}

// SubmitRemoteTelemetry atomically accepts existing billable usage plus a
// separate, signed pressure observation under the SAME server-issued nonce.
// Rejection of either proof rolls back both ingestion operations; a missing
// optional pressure report cannot create a trusted demand observation.
func SubmitRemoteTelemetry(ctx context.Context, db *sql.DB, authenticatedNode uuid.UUID,
	b RemoteBinding, evidence, pressure []byte) (Receipt, error) {
	if len(pressure) != 120+ed25519.SignatureSize {
		return Receipt{}, ErrRemoteEvidence
	}
	return submitRemoteTelemetry(ctx, db, authenticatedNode, b, evidence, pressure)
}

func submitRemoteTelemetry(ctx context.Context, db *sql.DB, authenticatedNode uuid.UUID,
	b RemoteBinding, evidence, pressure []byte) (Receipt, error) {
	if db == nil || !b.valid(authenticatedNode) || len(evidence) != 48+ed25519.SignatureSize {
		return Receipt{}, ErrSample
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil {
		return Receipt{}, err
	}
	defer tx.Rollback()
	period, _, err := remoteBindingPeriod(ctx, tx, b)
	if err != nil {
		return Receipt{}, err
	}
	subscription, key, err := remoteSubscription(ctx, tx, b, period)
	if err != nil {
		return Receipt{}, err
	}
	var nonce string
	var expires time.Time
	var challengePeriod uuid.UUID
	err = tx.QueryRowContext(ctx, `SELECT nonce,expires_at,period_id
		FROM elx_remote_usage_challenges
		WHERE node_id=$1 AND executor_id=$2 AND incarnation=$3 AND accounting_id=$4
		  AND generation=$5 AND schedule_id=$6 FOR UPDATE`,
		b.NodeID, b.ExecutorID, b.Incarnation, b.AccountingID, b.Generation, b.ScheduleID).
		Scan(&nonce, &expires, &challengePeriod)
	if errors.Is(err, sql.ErrNoRows) {
		return Receipt{}, ErrRemoteChallenge
	}
	if err != nil {
		return Receipt{}, err
	}
	var now time.Time
	if err := tx.QueryRowContext(ctx, `SELECT clock_timestamp()`).Scan(&now); err != nil {
		return Receipt{}, err
	}
	if challengePeriod != period || !expires.After(now) {
		return Receipt{}, ErrRemoteChallenge
	}
	sample, err := corepolicy.VerifyUsageEvidence(subscription, nonce, ed25519.PublicKey(key), evidence)
	if err != nil || sample.Incarnation != b.Incarnation || sample.SampledAt.After(now.Add(5*time.Second)) {
		return Receipt{}, ErrRemoteEvidence
	}
	var pressureSample corepolicy.PressureSample
	if len(pressure) != 0 {
		pressureSample, err = corepolicy.VerifyPressureEvidence(subscription, nonce,
			ed25519.PublicKey(key), pressure)
		if err != nil || pressureSample.Incarnation != b.Incarnation ||
			pressureSample.Sequence <= uint64(sample.Sequence) ||
			pressureSample.SampledAt.Before(sample.SampledAt) ||
			pressureSample.SampledAt.After(now.Add(5*time.Second)) {
			return Receipt{}, ErrRemoteEvidence
		}
	}
	value := Sample{
		NodeID: b.NodeID, ExecutorID: b.ExecutorID, Incarnation: b.Incarnation,
		AccountingID: b.AccountingID, Generation: b.Generation, PeriodID: period,
		Sequence: sample.Sequence, SampledAt: sample.SampledAt,
		UpBytes: sample.UpBytes, DownBytes: sample.DownBytes,
	}
	if err := validateSample(authenticatedNode, value); err != nil {
		return Receipt{}, err
	}
	result, err := ingestSample(ctx, tx, value)
	if err != nil {
		return Receipt{}, err
	}
	if len(pressure) != 0 {
		if err := persistRemotePressure(ctx, tx, b, period, pressureSample); err != nil {
			return Receipt{}, err
		}
	}
	row, err := tx.ExecContext(ctx, `DELETE FROM elx_remote_usage_challenges
		WHERE node_id=$1 AND executor_id=$2 AND incarnation=$3 AND accounting_id=$4
		AND generation=$5 AND schedule_id=$6 AND nonce=$7`,
		b.NodeID, b.ExecutorID, b.Incarnation, b.AccountingID, b.Generation, b.ScheduleID, nonce)
	if err != nil {
		return Receipt{}, err
	}
	n, err := row.RowsAffected()
	if err != nil {
		return Receipt{}, err
	}
	if n != 1 {
		return Receipt{}, ErrRemoteChallenge
	}
	if err := tx.Commit(); err != nil {
		return Receipt{}, err
	}
	return result, nil
}
