package journal

import (
	"context"
	"database/sql"
)

// PendingRateWitnessEligible permits independent HWM attestation of the
// PREVIOUS committed core revision only while an exactly matching next
// revision rate move has been durably budget-reserved and remains INTENT.
// It never asserts the pending operation was applied or releases bandwidth.
// A foreign/unknown pending mutation may not obtain an apparent stable HWM.
func PendingRateWitnessEligible(ctx context.Context, db *sql.DB,
	target Target, operationID string, epoch int64,
) (bool, error) {
	if db == nil || !validRateTarget(target) || !uuidValid(operationID) || epoch <= 0 {
		return false, ErrInvalid
	}
	var eligible bool
	err := db.QueryRowContext(ctx, `SELECT EXISTS (
		SELECT 1 FROM elx_rate_moves m
		JOIN elx_operations o ON o.node_id=m.node_id
		  AND o.resource_id=m.resource_id AND o.operation_id=m.operation_id
		JOIN elx_core_store_witnesses w ON w.node_id=o.node_id
		  AND w.resource_id=o.resource_id
		JOIN elx_rate_grants g ON g.node_id=o.node_id
		  AND g.resource_id=o.resource_id
		WHERE o.node_id=$1 AND o.resource_id=$2 AND o.operation_id=$3
		  AND m.finalized=false AND o.applied_at IS NULL
		  AND o.revision-1=w.core_revision
		  AND w.authority_generation=g.epoch AND g.epoch=$4
	)`, target.NodeID, target.ResourceID, operationID, epoch).Scan(&eligible)
	return eligible, err
}
