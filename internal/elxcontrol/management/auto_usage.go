package management

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/ElXnet/ElX-control/internal/elxcontrol/journal"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/policytransport"
	"github.com/google/uuid"
)

// AutoProvisionFromBindings consumes exactly the same trusted policy manifest
// used by serve-policy. It does NOT read subscription IDs from /sub, devices,
// URLs, IP addresses or a client-supplied payload.
//
// The manifest must cover every active rate grant on the entitlement. Missing
// grants fail closed *before* any stream is created. Applying individual
// assignments remains idempotent across a database/network interruption;
// incomplete coverage cannot activate a staged FUP schedule.
func (s SQLStore) AutoProvisionFromBindings(
	ctx context.Context, entitlement, schedule string,
	bindings []policytransport.Binding,
) ([]UsageProvisioned, error) {
	if s.DB == nil || !canonical(entitlement) || !canonical(schedule) ||
		len(bindings) == 0 || len(bindings) > 10000 {
		return nil, journal.ErrInvalid
	}
	if err := policytransport.ValidateBindings(bindings); err != nil {
		return nil, fmt.Errorf("%w: invalid trusted policy manifest: %v", journal.ErrInvalid, err)
	}
	// The schedule is selected by Control, not by a node. Ensure that it
	// belongs to the same purchased entitlement before inspecting bindings.
	var active string
	err := s.DB.QueryRowContext(ctx, `SELECT s.current_period_id::text
		FROM elx_period_schedules s JOIN elx_usage_periods p ON p.id=s.current_period_id
		JOIN elx_entitlements e ON e.id=s.entitlement_id
		WHERE s.id=$1 AND s.entitlement_id=$2 AND e.enabled
		  AND e.valid_until>clock_timestamp()
		  AND p.starts_at<=clock_timestamp() AND p.ends_at>clock_timestamp()`,
		schedule, entitlement).Scan(&active)
	if errors.Is(err, sql.ErrNoRows) { return nil, ErrSchedule }
	if err != nil { return nil, err }

	type grant struct {
		node, resource string
		epoch int64
		public []byte
	}
	rows, err := s.DB.QueryContext(ctx, `SELECT node_id::text,resource_id::text,epoch,barrier_public_key
		FROM elx_rate_grants WHERE entitlement_id=$1
		  AND committed_up>0 AND committed_down>0
		ORDER BY node_id,resource_id LIMIT 10001`, entitlement)
	if err != nil { return nil, err }
	var grants []grant
	for rows.Next() {
		var g grant
		if err := rows.Scan(&g.node,&g.resource,&g.epoch,&g.public); err != nil {
			rows.Close()
			return nil, err
		}
		grants = append(grants, g)
	}
	err = rows.Err()
	rows.Close()
	if err != nil { return nil, err }
	if len(grants) == 0 || len(grants) > 10000 { return nil, journal.ErrInvalid }

	byTarget := make(map[journal.Target]policytransport.Binding, len(bindings))
	for _, binding := range bindings { byTarget[binding.Target] = binding }
	planned := make([]UsageProvision, 0, len(grants))
	for _, g := range grants {
		b, found := byTarget[journal.Target{NodeID:g.node, ResourceID:g.resource}]
		if !found || g.epoch != b.Epoch || !bytes.Equal(g.public, b.PublicKey) {
			return nil, journal.ErrConflict
		}
		// A key can identify only one current boot on a node. If two
		// incarnations are registered against the same key, refuse to guess
		// which counter reset boundary or VPN core actually owns the traffic.
		ids, err := s.DB.QueryContext(ctx, `SELECT incarnation::text FROM elx_core_identities
			WHERE node_id=$1 AND public_key=$2 AND revoked=false
			ORDER BY registered_at DESC, incarnation LIMIT 2`, g.node, g.public)
		if err != nil { return nil, err }
		var boots []string
		for ids.Next() {
			var boot string
			if err := ids.Scan(&boot); err != nil { ids.Close(); return nil, err }
			boots = append(boots, boot)
		}
		err = ids.Err()
		ids.Close()
		if err != nil { return nil, err }
		if len(boots) != 1 { return nil, journal.ErrConflict }
		// UUIDv5 identities are stable across coordinator retries and
		// independent of user data. Each core boot obtains a separate stream,
		// so cumulative counters can never be confused across incarnations.
		executor := uuid.NewSHA1(uuid.NameSpaceURL,
			[]byte("elx-control/v1/usage-executor/"+g.node))
		stream := uuid.NewSHA1(uuid.NameSpaceURL,
			[]byte("elx-control/v1/usage-stream/"+g.node+"/"+g.resource+"/"+boots[0]))
		planned = append(planned, UsageProvision{
			ScheduleID:schedule, NodeID:g.node, ResourceID:g.resource,
			ExecutorID:executor.String(), Incarnation:boots[0],
			AccountingID:stream.String(), Generation:g.epoch,
			SubscriptionID:b.Subscription,
			ExpectedEpoch:g.epoch, ExpectedPublicKey:append([]byte(nil),g.public...),
		})
	}
	// Writes happen only after full manifest coverage and pinned-identity
	// validation; each write re-checks the grant and core inside its own
	// transaction. No partial outcome becomes active unless FUP activation
	// independently validates complete, fresh signed coverage.
	result := make([]UsageProvisioned, 0, len(planned))
	for _, req := range planned {
		provisioned, err := s.ProvisionUsageStream(ctx, entitlement, req)
		if err != nil { return nil, fmt.Errorf("provision %s/%s: %w", req.NodeID,req.ResourceID,err) }
		result = append(result, provisioned)
	}
	return result, nil
}
