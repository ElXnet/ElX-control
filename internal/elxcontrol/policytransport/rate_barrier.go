package policytransport

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/corepolicy"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/journal"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type RateBarrierJob struct {
	Request corepolicy.RateBarrierRequest
	PublicKey []byte
}
type rateBarrierReceipt struct {
	ResourceID string
	OperationID uuid.UUID
	Signature []byte
}

func (s *server) rateJob(ctx context.Context,b Binding,operation uuid.UUID)(RateBarrierJob,error){
	var job RateBarrierJob
	var ent uuid.UUID
	var op uuid.UUID
	var epoch,revision,up,down int64
	query:=`SELECT g.entitlement_id,g.epoch,o.revision,m.operation_id,m.desired_up,m.desired_down
		FROM elx_rate_grants g JOIN elx_rate_moves m
			ON m.node_id=g.node_id AND m.resource_id=g.resource_id
		JOIN elx_operations o ON o.node_id=m.node_id AND o.resource_id=m.resource_id
			AND o.operation_id=m.operation_id
		WHERE g.node_id=$1 AND g.resource_id=$2 AND m.finalized=false
			AND o.applied_at IS NOT NULL`
	params:=[]any{b.Target.NodeID,b.Target.ResourceID}
	if operation!=uuid.Nil {
		query+=` AND m.operation_id=$3`
		params=append(params,operation)
	}
	query+=` ORDER BY o.revision LIMIT 1`
	err:=s.db.QueryRowContext(ctx,query,params...).Scan(&ent,&epoch,&revision,&op,&up,&down)
	if err!=nil{return job,err}
	node,err:=uuid.Parse(b.Target.NodeID)
	if err!=nil{return job,err}
	resource,err:=uuid.Parse(b.Target.ResourceID)
	if err!=nil{return job,err}
	job.Request=corepolicy.RateBarrierRequest{
		EntitlementID:ent, NodeID:node, ResourceID:resource, OperationID:op,
		Subscription:b.Subscription, Epoch:epoch,Revision:revision,
		CoreRevision:revision+1,Up:up,Down:down,
	}
	job.PublicKey=append([]byte(nil),b.PublicKey...)
	return job,nil
}

func (s *server) nextRateBarrier(ctx context.Context,_ *emptypb.Empty)(*wrapperspb.BytesValue,error){
	bindings,err:=s.authorize(ctx)
	if err!=nil{return nil,err}
	for _,b:=range bindings {
		job,err:=s.rateJob(ctx,b,uuid.Nil)
		if errors.Is(err,sql.ErrNoRows){continue}
		if err!=nil{return nil,status.Error(codes.Unavailable,"rate barrier journal unavailable")}
		data,err:=json.Marshal(job)
		if err!=nil{return nil,status.Error(codes.Internal,"rate barrier encoding failed")}
		return wrapperspb.Bytes(data),nil
	}
	return nil,status.Error(codes.NotFound,"no applied rate move requires finalization")
}

func (s *server) confirmRateBarrier(ctx context.Context,in *wrapperspb.BytesValue)(*emptypb.Empty,error){
	bindings,err:=s.authorize(ctx)
	if err!=nil{return nil,err}
	if len(in.GetValue())>1024 {return nil,status.Error(codes.InvalidArgument,"barrier too large")}
	var input rateBarrierReceipt
	if json.Unmarshal(in.GetValue(),&input)!=nil || !validID(input.ResourceID) ||
		input.OperationID==uuid.Nil || len(input.Signature)!=ed25519.SignatureSize {
		return nil,status.Error(codes.InvalidArgument,"invalid signed rate barrier receipt")
	}
	for _,b:=range bindings {
		if b.Target.ResourceID!=input.ResourceID{continue}
		job,err:=s.rateJob(ctx,b,input.OperationID)
		if errors.Is(err,sql.ErrNoRows){return nil,status.Error(codes.FailedPrecondition,"barrier operation not applied")}
		if err!=nil{return nil,status.Error(codes.Unavailable,"rate barrier journal unavailable")}
		if !ed25519.Verify(b.PublicKey,corepolicy.BarrierTranscript(job.Request),input.Signature){
			return nil,status.Error(codes.PermissionDenied,"rate barrier signature mismatch")
		}
		err=journal.FinalizeRateMove(ctx,s.db,job.Request.EntitlementID.String(),b.Target,
			input.OperationID.String(),input.Signature)
		if err!=nil{return nil,status.Error(codes.FailedPrecondition,"rate budget not safe to finalize")}
		return &emptypb.Empty{},nil
	}
	return nil,status.Error(codes.PermissionDenied,"rate target belongs to a different node")
}

type RateBarrierCore interface {
	ProveRateBarrier(context.Context,corepolicy.RateBarrierRequest,ed25519.PublicKey)([]byte,error)
}

// ApplyRateBarrier obtains only previously applied operations from Control,
// asks the core for the exact signed deny+drain barrier, and finalizes the
// reserved budget only after the central ledger independently verifies it.
func ApplyRateBarrier(ctx context.Context,conn grpc.ClientConnInterface,core RateBarrierCore)error{
	if conn==nil||core==nil{return errors.New("rate barrier requires Control and local ElXray")}
	var raw wrapperspb.BytesValue
	if err:=conn.Invoke(ctx,"/"+serviceName+"/RateBarrierNext",&emptypb.Empty{},&raw);err!=nil{return err}
	var job RateBarrierJob
	if json.Unmarshal(raw.Value,&job)!=nil || len(job.PublicKey)!=ed25519.PublicKeySize ||
		job.Request.OperationID==uuid.Nil || job.Request.CoreRevision<=1 {
		return errors.New("invalid Control rate-barrier assignment")
	}
	proof,err:=core.ProveRateBarrier(ctx,job.Request,ed25519.PublicKey(job.PublicKey))
	if err!=nil{return err}
	p,err:=json.Marshal(rateBarrierReceipt{
		ResourceID:job.Request.ResourceID.String(),OperationID:job.Request.OperationID,Signature:proof,
	})
	if err!=nil{return err}
	return conn.Invoke(ctx,"/"+serviceName+"/RateBarrierConfirm",wrapperspb.Bytes(p),&emptypb.Empty{})
}
