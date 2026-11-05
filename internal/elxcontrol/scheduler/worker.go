// Package scheduler runs the Control-side, leader-fenced bandwidth
// reconciliation loop. It never accepts rate claims from a web client.
package scheduler

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/ElXnet/ElX-control/internal/elxcontrol/journal"
	"github.com/google/uuid"
)

const maxEntitlementsPerPass=10000

type Worker struct {
	DB *sql.DB
	Holder uuid.UUID
	Interval time.Duration
	LeaderTTL time.Duration
	// OnDecision is optional, for audit/metrics integration. It runs AFTER
	// the journal commits; it must never supply or mutate authorization.
	OnDecision func(string,journal.DemandRebalanceResult)
}

type Sweep struct {
	Entitlements int
	Queued int
	Waiting int
	Frozen int
	Contended int
}

// TickOnce performs one finite pass, acquiring/renewing an independent
// PostgreSQL leader epoch per entitlement. This is safe with multiple Control
// instances: the journal's budget row and leader row serialize every enqueue.
func (w *Worker) TickOnce(ctx context.Context) (Sweep,error) {
	var result Sweep
	if w.DB==nil || w.Holder==uuid.Nil ||
		w.LeaderTTL<5*time.Second || w.LeaderTTL>30*time.Second {
		return result,journal.ErrInvalid
	}
	rows,err:=w.DB.QueryContext(ctx,`SELECT b.entitlement_id::text
		FROM elx_rate_budgets b JOIN elx_entitlements e ON e.id=b.entitlement_id
		WHERE e.enabled AND e.valid_until>clock_timestamp()
		ORDER BY b.entitlement_id LIMIT 10001`)
	if err!=nil{return result,err}
	entitlements:=make([]string,0)
	for rows.Next() {
		var entitlement string
		if err:=rows.Scan(&entitlement);err!=nil{
			rows.Close()
			return result,err
		}
		entitlements=append(entitlements,entitlement)
		if len(entitlements)>maxEntitlementsPerPass{
			rows.Close()
			return result,fmt.Errorf("scheduler scope exceeds %d entitlements; adjust pagination before enabling",maxEntitlementsPerPass)
		}
	}
	err=rows.Err()
	rows.Close()
	if err!=nil{return result,err}
	for _,entitlement:=range entitlements{
		if err:=ctx.Err();err!=nil{return result,err}
		result.Entitlements++
		lease,err:=journal.AcquireSchedulerLease(ctx,w.DB,entitlement,w.Holder,w.LeaderTTL)
		if errors.Is(err,journal.ErrSchedulerBusy) {
			result.Contended++
			continue
		}
		if errors.Is(err,journal.ErrInactiveRateEntitlement) {
			continue
		}
		if err!=nil{return result,fmt.Errorf("acquire scheduler lease for %s: %w",entitlement,err)}
		decision,err:=journal.RebalanceAttestedDemand(ctx,w.DB,entitlement,lease)
		if errors.Is(err,journal.ErrSchedulerFenced) {
			// We may have paused past the lease deadline. Do not retry the
			// move without acquiring a new fence on the next pass.
			result.Contended++
			continue
		}
		if errors.Is(err,journal.ErrInactiveRateEntitlement){
			continue
		}
		if err!=nil{return result,fmt.Errorf("verified rebalance for %s: %w",entitlement,err)}
		result.Frozen+=decision.FrozenTargets
		if decision.OperationID!=""{result.Queued++}
		if decision.Phase=="waiting"{result.Waiting++}
		if w.OnDecision!=nil{w.OnDecision(entitlement,decision)}
	}
	return result,nil
}

// Run is a foreground supervisor-controlled worker. A PostgreSQL error
// causes an exit; it never continues granting from cached rates or leases.
// No process is started automatically by linking the package: the operator
// must explicitly run the guarded serve-scheduler command.
func (w *Worker) Run(ctx context.Context) error {
	if w.Interval<time.Second || w.Interval>time.Minute {
		return journal.ErrInvalid
	}
	ticker:=time.NewTicker(w.Interval)
	defer ticker.Stop()
	for {
		if err:=ctx.Err();err!=nil{return nil}
		if _,err:=w.TickOnce(ctx);err!=nil{
			if ctx.Err()!=nil{return nil}
			return err
		}
		select {
		case <-ctx.Done():return nil
		case <-ticker.C:
		}
	}
}
