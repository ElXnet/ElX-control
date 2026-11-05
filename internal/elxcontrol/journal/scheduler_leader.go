package journal

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"time"

	"github.com/google/uuid"
)

var (
	ErrSchedulerFenced = errors.New("scheduler leader epoch is expired or fenced")
	ErrSchedulerBusy   = errors.New("another scheduler currently owns this entitlement")
)

const (
	minSchedulerTTL = 5*time.Second
	maxSchedulerTTL = 30*time.Second
)

// SchedulerLease identifies a durable leader epoch. Unlike an ordinary RPC
// or process-local mutex, the epoch invalidates a former leader after takeover.
type SchedulerLease struct {
	EntitlementID string
	HolderID uuid.UUID
	Epoch int64
	ExpiresAt time.Time
}

func validSchedulerLease(lease SchedulerLease) bool {
	id, err := uuid.Parse(lease.EntitlementID)
	return err == nil && id != uuid.Nil && id.String() == lease.EntitlementID &&
		lease.HolderID != uuid.Nil && lease.Epoch > 0
}

// AcquireSchedulerLease grants leadership for one entitlement. Only its
// current holder can renew before expiry; takeover increments the epoch even
// if the previous holder reacquires after a timeout. All replica clocks use
// PostgreSQL clock_timestamp() rather than local host timestamps.
func AcquireSchedulerLease(ctx context.Context, db *sql.DB, entitlement string,
	holder uuid.UUID, ttl time.Duration) (SchedulerLease, error) {
	result := SchedulerLease{}
	id, err := uuid.Parse(entitlement)
	if db == nil || err != nil || id == uuid.Nil || id.String() != entitlement ||
		holder == uuid.Nil || ttl < minSchedulerTTL || ttl > maxSchedulerTTL {
		return result, ErrInvalid
	}
	tx, err := db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelReadCommitted})
	if err != nil { return result, err }
	defer tx.Rollback()
	if _, err = lockBudget(ctx,tx,entitlement); err != nil {return result,err}
	var now time.Time
	var enabled bool
	var validUntil time.Time
	err = tx.QueryRowContext(ctx,`SELECT enabled,valid_until,clock_timestamp()
		FROM elx_entitlements WHERE id=$1`,entitlement).Scan(&enabled,&validUntil,&now)
	if err != nil {return result,err}
	if !enabled || !validUntil.After(now) {return result,ErrInactiveRateEntitlement}
	// ON CONFLICT DO NOTHING does not steal a live leader. The surrounding
	// budget lock serializes all leader acquisition and rate operations.
	expires := now.Add(ttl)
	_,err=tx.ExecContext(ctx,`INSERT INTO elx_rate_scheduler_leaders
		(entitlement_id,holder_id,epoch,expires_at)
		VALUES($1,$2,1,$3) ON CONFLICT(entitlement_id) DO NOTHING`,
		entitlement,holder,expires)
	if err!=nil {return result,err}
	var previousHolder uuid.UUID
	var previousEpoch int64
	var previousExpiry time.Time
	err=tx.QueryRowContext(ctx,`SELECT holder_id,epoch,expires_at
		FROM elx_rate_scheduler_leaders WHERE entitlement_id=$1 FOR UPDATE`,
		entitlement).Scan(&previousHolder,&previousEpoch,&previousExpiry)
	if err!=nil{return result,err}
	epoch:=previousEpoch
	if !previousExpiry.After(now) {
		if epoch==math.MaxInt64{return result,ErrSchedulerFenced}
		epoch++ // always fence the old token, including the same holder.
	} else if previousHolder!=holder {
		return result,ErrSchedulerBusy
	}
	_,err=tx.ExecContext(ctx,`UPDATE elx_rate_scheduler_leaders SET
		holder_id=$2,epoch=$3,expires_at=$4,updated_at=clock_timestamp()
		WHERE entitlement_id=$1`,entitlement,holder,epoch,expires)
	if err!=nil{return result,err}
	if err=tx.Commit();err!=nil{return result,err}
	return SchedulerLease{EntitlementID:entitlement,HolderID:holder,Epoch:epoch,ExpiresAt:expires},nil
}

// RenewSchedulerLease never permits a stale token to create a new epoch. The
// caller must explicitly reacquire after loss of leadership.
func RenewSchedulerLease(ctx context.Context, db *sql.DB, lease SchedulerLease, ttl time.Duration) (SchedulerLease,error) {
	if db==nil || !validSchedulerLease(lease) ||
		ttl<minSchedulerTTL || ttl>maxSchedulerTTL {
		return SchedulerLease{},ErrInvalid
	}
	tx,err:=db.BeginTx(ctx,&sql.TxOptions{Isolation:sql.LevelReadCommitted})
	if err!=nil{return SchedulerLease{},err}
	defer tx.Rollback()
	if _,err=lockBudget(ctx,tx,lease.EntitlementID);err!=nil{return SchedulerLease{},err}
	var now time.Time
	if err=tx.QueryRowContext(ctx,`SELECT clock_timestamp()`).Scan(&now);err!=nil{return SchedulerLease{},err}
	if err=verifySchedulerLeaseTx(ctx,tx,lease,now);err!=nil{return SchedulerLease{},err}
	var enabled bool
	var validUntil time.Time
	if err=tx.QueryRowContext(ctx,`SELECT enabled,valid_until FROM elx_entitlements
		WHERE id=$1`,lease.EntitlementID).Scan(&enabled,&validUntil);err!=nil{return SchedulerLease{},err}
	if !enabled || !validUntil.After(now) {return SchedulerLease{},ErrInactiveRateEntitlement}
	expires:=now.Add(ttl)
	_,err=tx.ExecContext(ctx,`UPDATE elx_rate_scheduler_leaders SET
		expires_at=$4,updated_at=clock_timestamp()
		WHERE entitlement_id=$1 AND holder_id=$2 AND epoch=$3`,
		lease.EntitlementID,lease.HolderID,lease.Epoch,expires)
	if err!=nil{return SchedulerLease{},err}
	if err=tx.Commit();err!=nil{return SchedulerLease{},err}
	lease.ExpiresAt=expires
	return lease,nil
}

func verifySchedulerLeaseTx(ctx context.Context, tx *sql.Tx, lease SchedulerLease, now time.Time) error {
	if !validSchedulerLease(lease){return ErrSchedulerFenced}
	var holder uuid.UUID
	var epoch int64
	var expiry time.Time
	err:=tx.QueryRowContext(ctx,`SELECT holder_id,epoch,expires_at
		FROM elx_rate_scheduler_leaders WHERE entitlement_id=$1 FOR UPDATE`,
		lease.EntitlementID).Scan(&holder,&epoch,&expiry)
	if errors.Is(err,sql.ErrNoRows){return ErrSchedulerFenced}
	if err!=nil{return err}
	// The DB lease is authoritative, never the caller-supplied expiry.
	// A 2-second safety margin prevents a near-expiry worker from queuing
	// an operation after it has effectively lost leader liveness.
	if holder!=lease.HolderID || epoch!=lease.Epoch ||
		!expiry.After(now.Add(2*time.Second)){
		return ErrSchedulerFenced
	}
	return nil
}
