// Package fencetransport receives signed proof of a drained ElXray session.
// The transport NEVER accepts a caller-supplied public key: Control resolves
// the trusted key of the exact node and core incarnation in PostgreSQL.
package fencetransport

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/nodeidentity"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/session"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const serviceName = "elx.node.v1.SessionFence"

type Receipt struct {
	Fence session.Fence
	Signature []byte
}

// Job is only generated from a Control-authorized draining owner. PublicKey
// is the pinned Ed25519 key for this exact core boot, not a client-provided
// replacement. A node additionally checks it against ElXray's signature.
type Job struct {
	Fence session.Fence
	PublicKey []byte
}

type service interface {
	next(context.Context, *emptypb.Empty) (*wrapperspb.BytesValue,error)
	submit(context.Context, *wrapperspb.BytesValue) (*emptypb.Empty,error)
}
type receiver struct{db *sql.DB}

// next returns only pending, explicitly queued session drains for this
// authenticated node. It never creates a drain from a node request.
func (s *receiver) next(ctx context.Context, _ *emptypb.Empty) (*wrapperspb.BytesValue,error) {
	nodeText,err:=nodeidentity.FromGRPC(ctx)
	if err!=nil {return nil,status.Error(codes.PermissionDenied,"verified node certificate required")}
	nodeID,err:=uuid.Parse(nodeText)
	if err!=nil || nodeID==uuid.Nil {return nil,status.Error(codes.PermissionDenied,"invalid node identity")}
	var j Job
	j.Fence.NodeID=nodeID
	err=s.db.QueryRowContext(ctx,`SELECT o.id,o.profile_id,o.generation,
		o.core_incarnation,c.public_key
		FROM elx_session_owners o
		JOIN elx_core_identities c ON c.node_id=o.node_id
			AND c.incarnation=o.core_incarnation
		WHERE o.node_id=$1 AND o.state='draining' AND o.profile_id IS NOT NULL
			AND o.core_incarnation IS NOT NULL AND c.revoked=false
		ORDER BY o.reserved_at,o.id LIMIT 1`,nodeID).
		Scan(&j.Fence.OwnerID,&j.Fence.ProfileID,&j.Fence.Generation,
			&j.Fence.Incarnation,&j.PublicKey)
	if errors.Is(err,sql.ErrNoRows) {return nil,status.Error(codes.NotFound,"no approved drain pending")}
	if err!=nil {return nil,status.Error(codes.Unavailable,"session journal unavailable")}
	if len(j.PublicKey)!=ed25519.PublicKeySize {
		return nil,status.Error(codes.FailedPrecondition,"untrusted core identity")
	}
	data,err:=json.Marshal(j)
	if err!=nil {return nil,status.Error(codes.Internal,"fence job serialization failed")}
	return wrapperspb.Bytes(data),nil
}


func (s *receiver) submit(ctx context.Context, in *wrapperspb.BytesValue) (*emptypb.Empty,error) {
	nodeText,err:=nodeidentity.FromGRPC(ctx)
	if err!=nil {return nil,status.Error(codes.PermissionDenied,"verified node certificate required")}
	nodeID,err:=uuid.Parse(nodeText)
	if err!=nil || nodeID==uuid.Nil {return nil,status.Error(codes.PermissionDenied,"invalid node identity")}
	if len(in.GetValue())>1024 {return nil,status.Error(codes.InvalidArgument,"session receipt too large")}
	var payload Receipt
	if json.Unmarshal(in.GetValue(),&payload)!=nil || payload.Fence.NodeID!=nodeID ||
		payload.Fence.OwnerID==uuid.Nil || payload.Fence.ProfileID==uuid.Nil || payload.Fence.Incarnation==uuid.Nil ||
		payload.Fence.Generation<=0 || len(payload.Signature)!=ed25519.SignatureSize {
		return nil,status.Error(codes.PermissionDenied,"session receipt does not match authenticated node")
	}
	var key []byte
	var revoked bool
	err=s.db.QueryRowContext(ctx,`SELECT public_key,revoked FROM elx_core_identities
		WHERE node_id=$1 AND incarnation=$2`,nodeID,payload.Fence.Incarnation).Scan(&key,&revoked)
	if errors.Is(err,sql.ErrNoRows) {return nil,status.Error(codes.PermissionDenied,"core identity not registered")}
	if err!=nil {return nil,status.Error(codes.Unavailable,"core identity store unavailable")}
	if revoked || len(key)!=ed25519.PublicKeySize {return nil,status.Error(codes.PermissionDenied,"core identity revoked")}
	if !ed25519.Verify(ed25519.PublicKey(key),session.FenceTranscript(payload.Fence),payload.Signature) {
		return nil,status.Error(codes.PermissionDenied,"session fence signature invalid")
	}
	// This rechecks the pinned key and session generation inside a transaction,
	// avoiding a revocation race between public-key read and slot release.
	if err:=session.ReleaseAfterFence(ctx,s.db,payload.Fence,ed25519.PublicKey(key),payload.Signature);err!=nil {
		if errors.Is(err,session.ErrFence) {
			return nil,status.Error(codes.FailedPrecondition,"session drain generation or identity not verified")
		}
		return nil,status.Error(codes.Unavailable,"session fence journal unavailable")
	}
	return &emptypb.Empty{},nil
}

func Register(g *grpc.Server,db *sql.DB) error {
	if g==nil || db==nil {return errors.New("session fence requires an mTLS gRPC server and journal")}
	g.RegisterService(&grpc.ServiceDesc{
		ServiceName:serviceName,HandlerType:(*service)(nil),
		Methods:[]grpc.MethodDesc{
			{MethodName:"Next",Handler:nextHandler},
			{MethodName:"Submit",Handler:handler},
		},
	},&receiver{db:db})
	return nil
}

func nextHandler(s any,ctx context.Context,decode func(any)error,intercept grpc.UnaryServerInterceptor)(any,error){
	input:=new(emptypb.Empty)
	if err:=decode(input);err!=nil {return nil,err}
	if intercept==nil {return s.(*receiver).next(ctx,input)}
	return intercept(ctx,input,&grpc.UnaryServerInfo{Server:s,
		FullMethod:"/"+serviceName+"/Next"},
		func(ctx context.Context,req any)(any,error){
			return s.(*receiver).next(ctx,req.(*emptypb.Empty))
		})
}

func handler(s any,ctx context.Context,decode func(any)error,intercept grpc.UnaryServerInterceptor)(any,error){
	var input wrapperspb.BytesValue
	if err:=decode(&input);err!=nil{return nil,err}
	if intercept==nil {return s.(*receiver).submit(ctx,&input)}
	return intercept(ctx,&input,&grpc.UnaryServerInfo{Server:s,
		FullMethod:"/"+serviceName+"/Submit"},
		func(ctx context.Context,req any)(any,error){
			return s.(*receiver).submit(ctx,req.(*wrapperspb.BytesValue))
		})
}

// Send relays evidence generated by the ElXray core ONLY AFTER its own
// deny+drain barrier completes. A supervisor MUST NOT generate a signature
// using a copied signing seed or infer drainage from ordinary policy ACKs.
func Send(ctx context.Context,conn grpc.ClientConnInterface,f session.Fence,signature []byte) error {
	if conn==nil || len(signature)!=ed25519.SignatureSize {return errors.New("core drain evidence required")}
	p,err:=json.Marshal(Receipt{Fence:f,Signature:signature})
	if err!=nil {return err}
	return conn.Invoke(ctx,"/"+serviceName+"/Submit",wrapperspb.Bytes(p),&emptypb.Empty{})
}

// Drainer requires the local ElXray's profile-specific durable denial and
// signed drain RPC. This can never be satisfied by a generic policy ACK.
type Drainer interface {
	DrainProfile(context.Context, session.Fence, ed25519.PublicKey) ([]byte,error)
}

// ApplyNext lets the node agent execute ONE Control-approved session drain.
// The core first stops the authenticated VLESS profile, then the node sends
// its signed receipt back. Lost ACKs are safe: Next returns the same owner
// while its durable journal remains in draining state.
func ApplyNext(ctx context.Context, conn grpc.ClientConnInterface, core Drainer) error {
	if conn==nil || core==nil {return errors.New("profile drain requires Control and local ElXray")}
	var response wrapperspb.BytesValue
	if err:=conn.Invoke(ctx,"/"+serviceName+"/Next",&emptypb.Empty{},&response);err!=nil {
		return err
	}
	if len(response.Value)>2048 {return errors.New("invalid Control drain job size")}
	var job Job
	if err:=json.Unmarshal(response.Value,&job);err!=nil || job.Fence.OwnerID==uuid.Nil ||
		job.Fence.ProfileID==uuid.Nil || job.Fence.NodeID==uuid.Nil ||
		job.Fence.Incarnation==uuid.Nil || job.Fence.Generation<=0 ||
		len(job.PublicKey)!=ed25519.PublicKeySize {
		return errors.New("invalid Control session drain binding")
	}
	signature,err:=core.DrainProfile(ctx,job.Fence,ed25519.PublicKey(job.PublicKey))
	if err!=nil {return fmt.Errorf("ElXray profile drain not finished: %w",err)}
	return Send(ctx,conn,job.Fence,signature)
}
