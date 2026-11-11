package policytransport

import (
	"context"
	"encoding/json"
	"errors"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// TechnicalRecoveryJob is an mTLS-delivered READ-ONLY request for a
// previously accepted core outcome. It cannot authorize AddUser, RemoveUser,
// an owner slot, an expanded lease or a new rate. Original signed grant expiry
// is intentionally irrelevant: the core uses only its immutable journal
// digest and the Control DB verifies the independently pinned proof.
type TechnicalRecoveryJob struct {
	Action              string
	OperationID         string
	ProfileID           string
	NodeID              string
	ResourceID          string
	ExecutorID          string
	SubscriptionID      string
	AuthorityGeneration uint64
}

// nextTechnicalRecovery returns a bounded set so one impossible/unknown
// operation cannot starve independent historical lost-ACK reconciliations.
func (s *server) nextTechnicalRecovery(ctx context.Context,
	_ *emptypb.Empty,
) (*wrapperspb.BytesValue, error) {
	bindings, err := s.authorize(ctx)
	if err != nil { return nil, err }
	if s.db == nil {
		return nil, status.Error(codes.FailedPrecondition, "technical recovery requires PostgreSQL")
	}
	out := make([]TechnicalRecoveryJob, 0, 8)
	for _, b := range bindings {
		if len(out) >= 8 { break }
		if !b.Valid() || !validID(b.ExecutorID) {
			return nil, status.Error(codes.FailedPrecondition, "invalid recovery executor binding")
		}
		rows, err := s.db.QueryContext(ctx, `SELECT
		    o.action,o.operation_id::text,p.profile_id::text,
		    p.node_id::text,p.resource_id::text,p.executor_id::text,
		    p.subscription_id,o.authority_generation
		    FROM elx_technical_profile_operations o
		    JOIN elx_technical_profiles p ON p.profile_id=o.profile_id
		    JOIN elx_core_store_witnesses w
		      ON w.node_id=p.node_id AND w.resource_id=p.resource_id
		    JOIN elx_rate_grants g
		      ON g.node_id=p.node_id AND g.resource_id=p.resource_id
		      AND g.entitlement_id=p.entitlement_id
		    WHERE p.node_id=$1 AND p.resource_id=$2
		      AND NOT EXISTS (SELECT 1 FROM elx_technical_node_quarantines q WHERE q.node_id=p.node_id)
		      AND p.executor_id=$3 AND p.subscription_id=$4
		      AND o.action IN ('install','retire') AND o.state='INTENT'
		      AND o.authority_generation=p.authority_generation
		      AND w.executor_id=p.executor_id
		      AND w.authority_generation=p.authority_generation
		      AND g.epoch=p.authority_generation
		      AND o.not_after < EXTRACT(EPOCH FROM clock_timestamp())
		    ORDER BY o.created_at,o.operation_id LIMIT $5`,
			b.Target.NodeID,b.Target.ResourceID,b.ExecutorID,b.Subscription,
			8-len(out))
		if err != nil {
			return nil,status.Error(codes.Unavailable, "technical recovery ledger unavailable")
		}
		for rows.Next() {
			var job TechnicalRecoveryJob
			if err=rows.Scan(&job.Action,&job.OperationID,&job.ProfileID,
				&job.NodeID,&job.ResourceID,&job.ExecutorID,&job.SubscriptionID,
				&job.AuthorityGeneration); err!=nil { break }
			if job.NodeID!=b.Target.NodeID || job.ResourceID!=b.Target.ResourceID ||
				job.ExecutorID!=b.ExecutorID || job.SubscriptionID!=b.Subscription ||
				uint64(b.Epoch)!=job.AuthorityGeneration ||
				!validID(job.OperationID) || !validID(job.ProfileID) {
				err=errors.New("recovery job escaped trusted manifest")
				break
			}
			out=append(out,job)
		}
		if err==nil { err=rows.Err() }
		rows.Close()
		if err!=nil {return nil,status.Error(codes.FailedPrecondition,"inconsistent technical recovery ledger")}
	}
	if len(out)==0 { return nil,status.Error(codes.NotFound,"no expired technical outcomes to reconcile") }
	data,err:=json.Marshal(out)
	if err!=nil || len(data)>4096 {
		return nil,status.Error(codes.ResourceExhausted,"technical recovery window too large")
	}
	return wrapperspb.Bytes(data),nil
}

// No core proof means no Control APPLIED transition or capacity release.
