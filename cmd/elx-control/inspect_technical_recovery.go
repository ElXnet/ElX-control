package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/journal"
)

// TechnicalRecoveryAuditRow is an operator-only, read-only projection of
// Control's intent ledger. It is NEVER evidence that ElXray installed or
// removed the VLESS user; only a pinned core-signed receipt can prove that.
type TechnicalRecoveryAuditRow struct {
	OperationID string `json:"operationId"`
	ProfileID string `json:"profileId"`
	ResourceID string `json:"resourceId"`
	ExecutorID string `json:"executorId"`
	Action string `json:"action"`
	ControlPhase string `json:"controlPhase"`
	NotAfter int64 `json:"notAfter"`
	Expired bool `json:"expired"`
	NextStep string `json:"nextStep"`
}

type TechnicalRecoveryAudit struct {
	NodeID string `json:"nodeId"`
	NodeQuarantined bool `json:"nodeQuarantined"`
	Pending []TechnicalRecoveryAuditRow `json:"pending"`
	// Capacity/owner release is never implied by an inspection.
	AuthorizedMutation bool `json:"authorizedMutation"`
}

func technicalRecoveryNextStep(action, phase string, expired bool) string {
	switch {
	case phase == "retiring" && action != "retire":
		return "manual_quarantine_review"
	case action == "prepare" && expired:
		return "manual_prepare_review"
	case action == "prepare":
		return "await_signed_prepare"
	case (action == "install" || action == "retire") && expired:
		return "read_only_core_proof_probe"
	case action == "install" || action == "retire":
		return "await_signed_delivery"
	default:
		return "manual_quarantine_review"
	}
}

// inspectTechnicalRecovery takes ONLY a canonical node UUID. It queries the
// PostgreSQL authority directly, never asks a node to replay a stale command.
// The output intentionally omits emails, secret keys and profile payload.
func inspectTechnicalRecovery(ctx context.Context, db *sql.DB, args []string) error {
	return inspectTechnicalRecoveryTo(ctx, db, args, os.Stdout)
}

// inspectTechnicalRecoveryTo accepts a writer for real PostgreSQL read-only
// acceptance testing. No node-side operation is replayed by this function.
func inspectTechnicalRecoveryTo(ctx context.Context, db *sql.DB, args []string, output io.Writer) error {
	if db == nil || output == nil || len(args) != 1 {
		return errors.New("usage: elx-control inspect-technical-recovery <node-uuid>")
	}
	node, err := uuid.Parse(args[0])
	if err != nil || node == uuid.Nil || node.String() != args[0] {
		return errors.New("inspect-technical-recovery requires a canonical node UUID")
	}
	queryCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	quarantined, err := journal.TechnicalNodeQuarantined(queryCtx, db, node.String())
	if err != nil {
		return fmt.Errorf("technical quarantine ledger unavailable: %w", err)
	}
	rows, err := db.QueryContext(queryCtx, `SELECT
		o.operation_id::text,p.profile_id::text,p.resource_id::text,p.executor_id::text,
		o.action,p.state,o.not_after,
		o.not_after < EXTRACT(EPOCH FROM clock_timestamp())
		FROM elx_technical_profile_operations o
		JOIN elx_technical_profiles p ON p.profile_id=o.profile_id
		WHERE p.node_id=$1 AND o.state='INTENT'
		ORDER BY o.created_at,o.operation_id LIMIT 129`, node.String())
	if err != nil {
		return fmt.Errorf("technical recovery ledger unavailable: %w", err)
	}
	defer rows.Close()
	report := TechnicalRecoveryAudit{NodeID: node.String(),
		Pending: make([]TechnicalRecoveryAuditRow, 0),
		NodeQuarantined: quarantined, AuthorizedMutation: false}
	for rows.Next() {
		var item TechnicalRecoveryAuditRow
		if err := rows.Scan(&item.OperationID,&item.ProfileID,
			&item.ResourceID,&item.ExecutorID,&item.Action,
			&item.ControlPhase,&item.NotAfter,&item.Expired); err != nil {
			return fmt.Errorf("cannot inspect technical recovery row: %w", err)
		}
		if !validRecoveryAuditRow(item) {
			return errors.New("invalid technical recovery identity or ledger phase")
		}
		item.NextStep = technicalRecoveryNextStep(item.Action,item.ControlPhase,item.Expired)
		if quarantined {
			item.NextStep = "operator_quarantined_node_decommission_review"
		}
		report.Pending = append(report.Pending,item)
		if len(report.Pending) > 128 {
			return errors.New("too many unresolved technical operations: narrow scope or review backlog before recovery")
		}
	}
	if err := rows.Err(); err != nil {
		return fmt.Errorf("technical recovery ledger interrupted: %w", err)
	}
	return json.NewEncoder(output).Encode(report)
}

func validRecoveryAuditRow(v TechnicalRecoveryAuditRow) bool {
	for _, raw := range []string{v.OperationID,v.ProfileID,v.ResourceID,v.ExecutorID} {
		id,err:=uuid.Parse(raw)
		if err!=nil || id==uuid.Nil || id.String()!=raw {return false}
	}
	if v.NotAfter <= 0 {return false}
	if v.Action!="prepare" && v.Action!="install" && v.Action!="retire" {return false}
	switch v.ControlPhase {
	case "prepared","installed","retiring","retired": return true
	default: return false
	}
}
