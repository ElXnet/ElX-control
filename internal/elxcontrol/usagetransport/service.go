// Package usagetransport receives signed ElXray counters from remote nodes.
// Only the local core can sign usage. A provisioned node must authenticate
// through mTLS; no subscription URL grants access to this service.
package usagetransport

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"

	"github.com/google/uuid"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/accounting"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/nodeidentity"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const serviceName = "elx.node.v1.SignedAccounting"

type submitRequest struct {
	Binding accounting.RemoteBinding
	Evidence []byte
}

type receiver struct{ db *sql.DB }

type service interface {
	challenge(context.Context, *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error)
	submit(context.Context, *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error)
}

func authenticatedNode(ctx context.Context) (uuid.UUID, error) {
	value, err := nodeidentity.FromGRPC(ctx)
	if err != nil {
		return uuid.Nil, status.Error(codes.PermissionDenied, "verified node certificate required")
	}
	id, err := uuid.Parse(value)
	if err != nil || id == uuid.Nil {
		return uuid.Nil, status.Error(codes.PermissionDenied, "invalid node identity")
	}
	return id, nil
}

func transportError(err error) error {
	switch {
	case errors.Is(err, accounting.ErrSample):
		return status.Error(codes.InvalidArgument, "invalid accounting source")
	case errors.Is(err, accounting.ErrRemoteEvidence):
		return status.Error(codes.PermissionDenied, "invalid signed usage")
	case errors.Is(err, accounting.ErrRemoteChallenge), errors.Is(err, accounting.ErrStream):
		return status.Error(codes.FailedPrecondition, "accounting assignment or challenge unavailable")
	case errors.Is(err, accounting.ErrRegression), errors.Is(err, accounting.ErrConflict):
		return status.Error(codes.FailedPrecondition, "usage high-watermark conflict")
	default:
		return status.Error(codes.Unavailable, "usage accounting unavailable")
	}
}

func (s *receiver) challenge(ctx context.Context, in *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error) {
	id, err := authenticatedNode(ctx)
	if err != nil { return nil, err }
	if len(in.GetValue()) > 1024 {
		return nil, status.Error(codes.InvalidArgument, "accounting request too large")
	}
	var binding accounting.RemoteBinding
	if json.Unmarshal(in.GetValue(), &binding) != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid accounting request")
	}
	challenge, err := accounting.IssueRemoteChallenge(ctx, s.db, id, binding)
	if err != nil { return nil, transportError(err) }
	payload, err := json.Marshal(challenge)
	if err != nil { return nil, status.Error(codes.Internal, "challenge serialization failed") }
	return wrapperspb.Bytes(payload), nil
}

func (s *receiver) submit(ctx context.Context, in *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error) {
	id, err := authenticatedNode(ctx)
	if err != nil { return nil, err }
	if len(in.GetValue()) > 2048 {
		return nil, status.Error(codes.InvalidArgument, "usage evidence too large")
	}
	var input submitRequest
	if json.Unmarshal(in.GetValue(), &input) != nil {
		return nil, status.Error(codes.InvalidArgument, "invalid usage evidence request")
	}
	receipt, err := accounting.SubmitRemoteUsage(ctx, s.db, id, input.Binding, input.Evidence)
	if err != nil { return nil, transportError(err) }
	payload, err := json.Marshal(receipt)
	if err != nil { return nil, status.Error(codes.Internal, "receipt serialization failed") }
	return wrapperspb.Bytes(payload), nil
}

func Register(g *grpc.Server, db *sql.DB) error {
	if g == nil || db == nil {
		return errors.New("signed usage service requires a gRPC server and PostgreSQL")
	}
	g.RegisterService(&grpc.ServiceDesc{
		ServiceName: serviceName,
		HandlerType: (*service)(nil),
		Methods: []grpc.MethodDesc{
			{MethodName: "Challenge", Handler: handler("Challenge", (*receiver).challenge)},
			{MethodName: "Submit", Handler: handler("Submit", (*receiver).submit)},
		},
	}, &receiver{db: db})
	return nil
}

func handler[Req, Resp any](method string, call func(*receiver, context.Context, *Req) (*Resp,error)) grpc.MethodHandler {
	return func(s any, ctx context.Context, decode func(any) error,
		intercept grpc.UnaryServerInterceptor) (any,error) {
		input := new(Req)
		if err := decode(input); err != nil { return nil, err }
		if intercept == nil {
			return call(s.(*receiver), ctx, input)
		}
		return intercept(ctx,input,&grpc.UnaryServerInfo{Server:s,
			FullMethod:"/"+serviceName+"/"+method},
			func(ctx context.Context, request any) (any,error) {
				return call(s.(*receiver), ctx, request.(*Req))
			})
	}
}

// EvidenceReader is the strictly local ElXray API. The remote caller carries
// opaque core-signed bytes; only Control authorizes and verifies the claim.
type EvidenceReader interface {
	ReadUsageEvidence(context.Context, string, string) ([]byte, error)
}

func PollOne(ctx context.Context, conn grpc.ClientConnInterface, core EvidenceReader,
	binding accounting.RemoteBinding) (accounting.Receipt, error) {
	if conn == nil || core == nil {
		return accounting.Receipt{}, errors.New("usage poller requires Control and local ElXray")
	}
	request, err := json.Marshal(binding)
	if err != nil { return accounting.Receipt{}, err }
	var answer wrapperspb.BytesValue
	err = conn.Invoke(ctx, "/"+serviceName+"/Challenge", wrapperspb.Bytes(request), &answer)
	if err != nil { return accounting.Receipt{}, err }
	var challenge accounting.RemoteChallenge
	if err := json.Unmarshal(answer.Value, &challenge); err != nil { return accounting.Receipt{}, err }
	if len(challenge.Nonce) != 32 || len(challenge.Subscription)==0 || len(challenge.Subscription)>1024 {
		return accounting.Receipt{}, errors.New("invalid server-issued usage challenge")
	}
	evidence, err := core.ReadUsageEvidence(ctx, challenge.Subscription, challenge.Nonce)
	if err != nil { return accounting.Receipt{}, err }
	payload, err := json.Marshal(submitRequest{Binding:binding, Evidence:evidence})
	if err != nil { return accounting.Receipt{}, err }
	var response wrapperspb.BytesValue
	if err := conn.Invoke(ctx, "/"+serviceName+"/Submit", wrapperspb.Bytes(payload), &response); err != nil {
		return accounting.Receipt{}, err
	}
	var receipt accounting.Receipt
	if err := json.Unmarshal(response.Value, &receipt); err != nil {
		return accounting.Receipt{}, err
	}
	return receipt,nil
}
