package management

import (
	"context"
	"database/sql"
	"errors"
	"strings"

	"github.com/ElXnet/ElX-control/internal/elxcontrol/accounting"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/journal"
	"github.com/google/uuid"
)

// UsageProvision is a privileged operator operation, not a customer API.
// SubscriptionID must be read from the trusted policy binding manifest for
// the exact (node, resource) grant, never from a public subscription URL.
type UsageProvision struct {
	ScheduleID     string
	NodeID         string
	ResourceID     string
	ExecutorID     string
	Incarnation    string
	AccountingID   string
	Generation     int64
	SubscriptionID string
}

type UsageProvisioned struct {
	Binding        accounting.RemoteBinding
	ResourceID     uuid.UUID
	SubscriptionID string
	PeriodID       uuid.UUID
	AlreadyExisted bool
	Primed         bool
}

// ProvisionUsageStream binds the presently pinned core and a purchased rate
// grant to one FUP schedule's current period. A missing or revoked core, a
// foreign grant, or an ambiguous rebind is rejected. New streams begin
// unprimed: their first *signed* cumulative sample becomes the baseline,
// never historical usage charged into the new period.
func (s SQLStore) ProvisionUsageStream(ctx context.Context, entitlement string, req UsageProvision) (UsageProvisioned, error) {
	var out UsageProvisioned
	if s.DB == nil || !canonical(entitlement) ||
		!canonical(req.ScheduleID) || !canonical(req.NodeID) ||
		!canonical(req.ResourceID) || !canonical(req.ExecutorID) ||
		!canonical(req.Incarnation) || !canonical(req.AccountingID) ||
		req.Generation < 1 || req.Generation > 1<<40 ||
		len(req.SubscriptionID) < 1 || len(req.SubscriptionID) > 1024 ||
		strings.TrimSpace(req.SubscriptionID) != req.SubscriptionID {
		return out, journal.ErrInvalid
	}
	for _, name := range []string{req.ScheduleID,req.NodeID,req.ResourceID,req.ExecutorID,req.Incarnation,req.AccountingID}{
		if name == "00000000-0000-0000-0000-000000000000" { return out,journal.ErrInvalid }
	}

	b := accounting.RemoteBinding{
		NodeID: uuid.MustParse(req.NodeID), ExecutorID: uuid.MustParse(req.ExecutorID),
		Incarnation: uuid.MustParse(req.Incarnation), AccountingID: uuid.MustParse(req.AccountingID),
		ScheduleID: uuid.MustParse(req.ScheduleID), Generation: req.Generation,
	}
	out.Binding = b
	out.ResourceID = uuid.MustParse(req.ResourceID)
	out.SubscriptionID = req.SubscriptionID
	tx,err:=s.DB.BeginTx(ctx,&sql.TxOptions{Isolation:sql.LevelReadCommitted})
	if err!=nil{return UsageProvisioned{},err}
	defer tx.Rollback()

	var entitlementID string
	err=tx.QueryRowContext(ctx,`SELECT id::text FROM elx_entitlements
		WHERE id=$1 AND enabled=true AND valid_until>clock_timestamp() FOR UPDATE`,entitlement).Scan(&entitlementID)
	if errors.Is(err,sql.ErrNoRows){return UsageProvisioned{},ErrNotFound}
	if err!=nil{return UsageProvisioned{},err}

	// The schedule row lock serializes provisioning against the rollover
	// worker. No caller can attach sources to an old or foreign period.
	var period uuid.UUID
	err=tx.QueryRowContext(ctx,`SELECT s.current_period_id
		FROM elx_period_schedules s JOIN elx_usage_periods p ON p.id=s.current_period_id
		WHERE s.id=$1 AND s.entitlement_id=$2
		AND p.entitlement_id=$2 AND p.starts_at<=clock_timestamp()
		AND p.ends_at>clock_timestamp() FOR UPDATE OF s`,
		b.ScheduleID,entitlement).Scan(&period)
	if errors.Is(err,sql.ErrNoRows){return UsageProvisioned{},ErrSchedule}
	if err!=nil{return UsageProvisioned{},err}
	out.PeriodID=period

	var up,down int64
	err=tx.QueryRowContext(ctx,`SELECT committed_up,committed_down FROM elx_rate_grants
		WHERE entitlement_id=$1 AND node_id=$2 AND resource_id=$3 FOR SHARE`,
		entitlement,b.NodeID,out.ResourceID).Scan(&up,&down)
	if errors.Is(err,sql.ErrNoRows){return UsageProvisioned{},journal.ErrConflict}
	if err!=nil{return UsageProvisioned{},err}
	if up<=0 || down<=0 {return UsageProvisioned{},journal.ErrConflict}

	var revoked bool
	err=tx.QueryRowContext(ctx,`SELECT revoked FROM elx_core_identities
		WHERE node_id=$1 AND incarnation=$2 FOR SHARE`,b.NodeID,b.Incarnation).Scan(&revoked)
	if errors.Is(err,sql.ErrNoRows)||revoked{return UsageProvisioned{},journal.ErrConflict}
	if err!=nil{return UsageProvisioned{},err}

	key:=[]any{b.NodeID,b.ExecutorID,b.Incarnation,b.AccountingID,b.Generation,period}
	var storedSub string
	var storedResource sql.NullString
	err=tx.QueryRowContext(ctx,`SELECT subscription_id,resource_id::text FROM elx_accounting_assignments
		WHERE node_id=$1 AND executor_id=$2 AND incarnation=$3
		AND accounting_id=$4 AND generation=$5 AND period_id=$6 FOR UPDATE`,key...).
		Scan(&storedSub,&storedResource)
	if err==nil {
		if storedSub!=req.SubscriptionID || !storedResource.Valid || storedResource.String!=req.ResourceID {
			return UsageProvisioned{},journal.ErrConflict
		}
		if err=tx.QueryRowContext(ctx,`SELECT primed FROM elx_accounting_streams
			WHERE node_id=$1 AND executor_id=$2 AND incarnation=$3
			AND accounting_id=$4 AND generation=$5 AND period_id=$6`,key...).Scan(&out.Primed);err!=nil{return UsageProvisioned{},err}
		out.AlreadyExisted=true
		return out,tx.Commit()
	}
	if !errors.Is(err,sql.ErrNoRows){return UsageProvisioned{},err}

	var occupied bool
	err=tx.QueryRowContext(ctx,`SELECT EXISTS(
		SELECT 1 FROM elx_accounting_streams WHERE node_id=$1 AND executor_id=$2
		AND incarnation=$3 AND accounting_id=$4 AND generation=$5 AND period_id=$6)`,
		key...).Scan(&occupied)
	if err!=nil{return UsageProvisioned{},err}
	if occupied{return UsageProvisioned{},journal.ErrConflict}

	// Prevent double charging one ElXray subscription under two accounting
	// streams or charging the same rate grant through two subscriptions.
	err=tx.QueryRowContext(ctx,`SELECT EXISTS(
		SELECT 1 FROM elx_accounting_assignments WHERE period_id=$1 AND node_id=$2
		AND (subscription_id=$3 OR resource_id=$4))`,
		period,b.NodeID,req.SubscriptionID,out.ResourceID).Scan(&occupied)
	if err!=nil{return UsageProvisioned{},err}
	if occupied{return UsageProvisioned{},journal.ErrConflict}

	_,err=tx.ExecContext(ctx,`INSERT INTO elx_accounting_streams
		(node_id,executor_id,incarnation,accounting_id,generation,period_id,primed)
		VALUES($1,$2,$3,$4,$5,$6,false)`,key...)
	if err!=nil{return UsageProvisioned{},err}
	args:=append(append([]any(nil),key...),req.SubscriptionID,out.ResourceID)
	_,err=tx.ExecContext(ctx,`INSERT INTO elx_accounting_assignments
		(node_id,executor_id,incarnation,accounting_id,generation,period_id,subscription_id,resource_id)
		VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,args...)
	if err!=nil{return UsageProvisioned{},err}
	if err=tx.Commit();err!=nil{return UsageProvisioned{},err}
	return out,nil
}

// SignedCoverage is intentionally a *readiness* snapshot, not proof of
// enforcement. The node must still run its authenticated signed-usage agent,
// and the ElXray core must enforce Control leases and rate policies.
type SignedCoverage struct {
	ScheduleID     string `json:"scheduleId"`
	ExpectedGrants int64  `json:"expectedGrants"`
	AssignedGrants int64  `json:"assignedGrants"`
	PrimedGrants   int64  `json:"primedGrants"`
	FreshGrants    int64  `json:"freshGrants"`
	Ready          bool   `json:"ready"`
}

func (s SQLStore) UsageCoverage(ctx context.Context,entitlement,schedule string)(SignedCoverage,error){
	out:=SignedCoverage{ScheduleID:schedule}
	if s.DB==nil || !canonical(entitlement) || !canonical(schedule){return out,journal.ErrInvalid}
	var period uuid.UUID
	err:=s.DB.QueryRowContext(ctx,`SELECT s.current_period_id FROM elx_period_schedules s
		JOIN elx_usage_periods p ON p.id=s.current_period_id
		WHERE s.id=$1 AND s.entitlement_id=$2
		AND p.starts_at<=clock_timestamp() AND p.ends_at>clock_timestamp()`,
		schedule,entitlement).Scan(&period)
	if errors.Is(err,sql.ErrNoRows){return out,ErrNotFound}
	if err!=nil{return out,err}
	err=s.DB.QueryRowContext(ctx,`SELECT
		(SELECT count(*) FROM elx_rate_grants g
			WHERE g.entitlement_id=$1 AND g.committed_up>0 AND g.committed_down>0),
		(SELECT count(*) FROM elx_accounting_assignments a
			JOIN elx_rate_grants g ON g.node_id=a.node_id AND g.resource_id=a.resource_id
			WHERE a.period_id=$2 AND g.entitlement_id=$1
			AND g.committed_up>0 AND g.committed_down>0),
		(SELECT count(*) FROM elx_accounting_assignments a
			JOIN elx_rate_grants g ON g.node_id=a.node_id AND g.resource_id=a.resource_id
			JOIN elx_accounting_streams st ON st.node_id=a.node_id
			AND st.executor_id=a.executor_id AND st.incarnation=a.incarnation
			AND st.accounting_id=a.accounting_id AND st.generation=a.generation
			AND st.period_id=a.period_id
			JOIN elx_core_identities c ON c.node_id=a.node_id AND c.incarnation=a.incarnation
			WHERE a.period_id=$2 AND g.entitlement_id=$1
			AND g.committed_up>0 AND g.committed_down>0
			AND st.primed AND NOT st.closed AND NOT c.revoked),
		(SELECT count(*) FROM elx_accounting_assignments a
			JOIN elx_rate_grants g ON g.node_id=a.node_id AND g.resource_id=a.resource_id
			JOIN elx_accounting_streams st ON st.node_id=a.node_id
			AND st.executor_id=a.executor_id AND st.incarnation=a.incarnation
			AND st.accounting_id=a.accounting_id AND st.generation=a.generation
			AND st.period_id=a.period_id
			JOIN elx_core_identities c ON c.node_id=a.node_id AND c.incarnation=a.incarnation
			WHERE a.period_id=$2 AND g.entitlement_id=$1
			AND g.committed_up>0 AND g.committed_down>0
			AND st.primed AND NOT st.closed AND NOT c.revoked
			AND st.last_received_at>=clock_timestamp()-interval '30 seconds')`,
		entitlement,period).Scan(&out.ExpectedGrants,&out.AssignedGrants,&out.PrimedGrants,&out.FreshGrants)
	if err!=nil{return out,err}
	out.Ready=out.ExpectedGrants>0 && out.ExpectedGrants==out.FreshGrants &&
		out.ExpectedGrants==out.PrimedGrants && out.ExpectedGrants==out.AssignedGrants
	return out,nil
}
