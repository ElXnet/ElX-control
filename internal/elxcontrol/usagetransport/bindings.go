package usagetransport

import (
	"context"
	"encoding/json"

	"github.com/ElXnet/ElX-control/internal/elxcontrol/accounting"
	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// bindings publishes only the Control-authoritative stream selectors for
// the mTLS-authenticated node. It never discloses subscription IDs, billing
// credentials, private keys, or streams belonging to another node. Nodes
// discover new assignments automatically; the master owns all mappings.
func (s *receiver) bindings(ctx context.Context, _ *emptypb.Empty) (*wrapperspb.BytesValue,error) {
	node,err:=authenticatedNode(ctx)
	if err!=nil{return nil,err}
	rows,err:=s.db.QueryContext(ctx,`SELECT a.executor_id,a.incarnation,a.accounting_id,a.generation,sc.id
		FROM elx_accounting_assignments a
		JOIN elx_period_schedules sc ON sc.current_period_id=a.period_id
		JOIN elx_usage_periods p ON p.id=a.period_id
		JOIN elx_rate_grants g ON g.node_id=a.node_id AND g.resource_id=a.resource_id
		JOIN elx_core_identities c ON c.node_id=a.node_id AND c.incarnation=a.incarnation
		JOIN elx_entitlements e ON e.id=g.entitlement_id AND e.id=sc.entitlement_id
		JOIN elx_accounting_streams st ON st.node_id=a.node_id
		  AND st.executor_id=a.executor_id AND st.incarnation=a.incarnation
		  AND st.accounting_id=a.accounting_id AND st.generation=a.generation
		  AND st.period_id=a.period_id
		WHERE a.node_id=$1 AND a.resource_id IS NOT NULL AND NOT c.revoked
		  AND NOT st.closed AND e.enabled AND e.valid_until>clock_timestamp()
		  AND p.starts_at<=clock_timestamp() AND p.ends_at>clock_timestamp()
		  AND g.committed_up>0 AND g.committed_down>0
		ORDER BY a.executor_id,a.accounting_id,sc.id LIMIT 1001`,node)
	if err!=nil{return nil,status.Error(codes.Unavailable,"authoritative usage assignments unavailable")}
	defer rows.Close()
	bindings:=make([]accounting.RemoteBinding,0)
	for rows.Next(){
		b:=accounting.RemoteBinding{NodeID:node}
		if err:=rows.Scan(&b.ExecutorID,&b.Incarnation,&b.AccountingID,&b.Generation,&b.ScheduleID);err!=nil{
			return nil,status.Error(codes.Unavailable,"invalid usage assignment data")
		}
		if !b.Valid(){return nil,status.Error(codes.FailedPrecondition,"untrusted usage assignment")}
		bindings=append(bindings,b)
	}
	if err:=rows.Err();err!=nil{return nil,status.Error(codes.Unavailable,"cannot read usage assignments")}
	if len(bindings)>1000{return nil,status.Error(codes.ResourceExhausted,"too many signed usage assignments")}
	payload,err:=json.Marshal(bindings)
	if err!=nil{return nil,status.Error(codes.Internal,"cannot encode usage assignments")}
	// Defend the node against accidentally loading a huge or corrupted
	// trusted database response. The client repeats this bound locally.
	if len(payload)>1<<20{return nil,status.Error(codes.ResourceExhausted,"usage assignment response too large")}
	return wrapperspb.Bytes(payload),nil
}

// Verify compile-time dependency on the trusted wire UUID type.
var _ uuid.UUID
