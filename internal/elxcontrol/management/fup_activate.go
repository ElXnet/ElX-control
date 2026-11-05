package management

import (
	"context"
	"database/sql"
	"errors"

	"github.com/ElXnet/ElX-control/internal/elxcontrol/journal"
)

var ErrNotReady = errors.New("signed FUP source coverage is not ready")

type Activation struct {
	ScheduleID string `json:"scheduleId"`
	Enabled bool `json:"enabled"`
	AlreadyEnabled bool `json:"alreadyEnabled"`
	Coverage SignedCoverage `json:"coverage"`
}

// ActivateSchedule is an operator-only transition. It cannot turn on FUP
// until every purchased rate grant has a recent signed usage sequence from
// an enrolled, unrevoked core. The entitlement/budget/schedule locks prevent
// trusted provisioning from changing beneath the activation. Subsequent
// loss of freshness is enforced by the short-lived Control lease gate.
func (s SQLStore) ActivateSchedule(ctx context.Context,entitlement,schedule string)(Activation,error){
	result:=Activation{ScheduleID:schedule}
	if s.DB==nil||!canonical(entitlement)||!canonical(schedule){return result,journal.ErrInvalid}
	tx,err:=s.DB.BeginTx(ctx,&sql.TxOptions{Isolation:sql.LevelSerializable})
	if err!=nil{return result,err}
	defer tx.Rollback()
	var owned string
	err=tx.QueryRowContext(ctx,`SELECT id::text FROM elx_entitlements
		WHERE id=$1 AND enabled AND valid_until>clock_timestamp() FOR UPDATE`,entitlement).Scan(&owned)
	if errors.Is(err,sql.ErrNoRows){return result,ErrNotFound}
	if err!=nil{return result,err}
	var enabled bool
	err=tx.QueryRowContext(ctx,`SELECT s.enabled FROM elx_period_schedules s
		JOIN elx_usage_periods p ON p.id=s.current_period_id
		WHERE s.id=$1 AND s.entitlement_id=$2
		AND p.starts_at<=clock_timestamp() AND p.ends_at>clock_timestamp()
		FOR UPDATE OF s`,schedule,entitlement).Scan(&enabled)
	if errors.Is(err,sql.ErrNoRows){return result,ErrNotFound}
	if err!=nil{return result,err}
	// Keep the same lock order as signed CollectCurrent: schedule, then
	// rate budget. A concurrent fresh sample must not deadlock activation.
	var capUp,capDown int64
	err=tx.QueryRowContext(ctx,`SELECT up_limit,down_limit
		FROM elx_rate_budgets WHERE entitlement_id=$1 FOR UPDATE`,entitlement).Scan(&capUp,&capDown)
	if errors.Is(err,sql.ErrNoRows)||capUp<=0||capDown<=0{return result,ErrSchedule}
	if err!=nil{return result,err}
	// Use the same transaction snapshot/locks for coverage and activation.
	// No other user can authorize a missing stream by choosing a different
	// entitlement, resource or core UUID.
	err=tx.QueryRowContext(ctx,`
		SELECT
		(SELECT count(*) FROM elx_rate_grants g WHERE g.entitlement_id=$1
		  AND g.committed_up>0 AND g.committed_down>0),
		(SELECT count(*) FROM elx_accounting_assignments a
		  JOIN elx_rate_grants g ON g.node_id=a.node_id AND g.resource_id=a.resource_id
		  JOIN elx_accounting_streams st ON st.node_id=a.node_id
		  AND st.executor_id=a.executor_id AND st.incarnation=a.incarnation
		  AND st.accounting_id=a.accounting_id AND st.generation=a.generation
		  AND st.period_id=a.period_id
		  JOIN elx_core_identities c ON c.node_id=a.node_id AND c.incarnation=a.incarnation
		  JOIN elx_period_schedules fs ON fs.current_period_id=a.period_id
		  WHERE fs.id=$2 AND fs.entitlement_id=$1 AND g.entitlement_id=$1
		  AND g.committed_up>0 AND g.committed_down>0
		  AND st.primed AND NOT st.closed AND NOT c.revoked
		  AND st.last_received_at>=clock_timestamp()-interval '30 seconds')`,
		entitlement,schedule).Scan(&result.Coverage.ExpectedGrants,&result.Coverage.FreshGrants)
	if err!=nil{return result,err}
	result.Coverage.ScheduleID=schedule
	result.Coverage.Ready=result.Coverage.ExpectedGrants>0 &&
		result.Coverage.ExpectedGrants==result.Coverage.FreshGrants
	if result.Coverage.Ready {
		result.Coverage.AssignedGrants=result.Coverage.FreshGrants
		result.Coverage.PrimedGrants=result.Coverage.FreshGrants
	}
	if !result.Coverage.Ready{return result,ErrNotReady}
	if enabled{
		result.Enabled=true
		result.AlreadyEnabled=true
		return result,tx.Commit()
	}
	_,err=tx.ExecContext(ctx,`UPDATE elx_period_schedules SET enabled=true
		WHERE id=$1 AND entitlement_id=$2`,schedule,entitlement)
	if err!=nil{return result,err}
	if err=tx.Commit();err!=nil{return Activation{},err}
	result.Enabled=true
	return result,nil
}
