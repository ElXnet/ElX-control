package journal

import (
	"context"
	"database/sql"
	"errors"

	"github.com/google/uuid"
)

var ErrFUPCoverage = errors.New("signed FUP coverage unavailable")

// SignedFUPLeaseReady checks every active rate grant for every active FUP
// schedule before Control renews a short-lived VPN lease. A missing,
// unprimed, stale, closed or revoked signed stream fails closed. This check
// alone is not a realtime policy acknowledgement: ElXray validates the
// lease and enforces the current policy independently.
//
// The requested subscription ID must also match the *exact* grant for which
// this node asks for a lease. It cannot substitute a different subscription
// ID for a fully accounted grant.
func SignedFUPLeaseReady(ctx context.Context,db *sql.DB,entitlement,node,resource,subscription string)(bool,error){
	if db==nil||subscription==""||len(subscription)>1024{
		return false,ErrFUPCoverage
	}
	for _,id:=range []string{entitlement,node,resource}{
		u,err:=uuid.Parse(id)
		if err!=nil||u==uuid.Nil||u.String()!=id{return false,ErrFUPCoverage}
	}
	var schedules,grants int64
	var missing bool
	err:=db.QueryRowContext(ctx,`
		WITH active_schedules AS (
			SELECT s.current_period_id FROM elx_period_schedules s
			JOIN elx_usage_periods p ON p.id=s.current_period_id
			WHERE s.entitlement_id=$1 AND s.enabled
			AND p.starts_at<=clock_timestamp() AND p.ends_at>clock_timestamp()
		), active_grants AS (
			SELECT node_id,resource_id FROM elx_rate_grants
			WHERE entitlement_id=$1 AND committed_up>0 AND committed_down>0
		), uncovered AS (
			SELECT 1 FROM active_schedules s CROSS JOIN active_grants g
			WHERE NOT EXISTS (
				SELECT 1 FROM elx_accounting_assignments a
				JOIN elx_accounting_streams st ON st.node_id=a.node_id
				  AND st.executor_id=a.executor_id AND st.incarnation=a.incarnation
				  AND st.accounting_id=a.accounting_id AND st.generation=a.generation
				  AND st.period_id=a.period_id
				JOIN elx_core_identities c ON c.node_id=a.node_id
				  AND c.incarnation=a.incarnation
				WHERE a.period_id=s.current_period_id
				  AND a.node_id=g.node_id AND a.resource_id=g.resource_id
				  AND st.primed AND NOT st.closed AND NOT c.revoked
				  AND st.last_received_at>=clock_timestamp()-interval '30 seconds'
				  AND (g.node_id<>$2::uuid OR g.resource_id<>$3::uuid
					   OR a.subscription_id=$4)
			)
		)
		SELECT (SELECT count(*) FROM active_schedules),
		       (SELECT count(*) FROM active_grants),
		       EXISTS(SELECT 1 FROM uncovered)`,
		entitlement,node,resource,subscription).Scan(&schedules,&grants,&missing)
	if err!=nil{return false,err}
	if schedules==0{return true,nil} // No scheduled FUP: legacy lease behavior.
	return grants>0 && !missing,nil
}
