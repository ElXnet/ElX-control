// Package policytransport exchanges durable policy commands with a provisioned node.
package policytransport

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"slices"

	"github.com/ElXnet/ElX-control/internal/elxcontrol/corepolicy"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/journal"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/nodeidentity"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const serviceName = "elx.node.v1.PolicyDelivery"

type Binding struct {
	Target       journal.Target
	Subscription string
	ExecutorID   string // assigned core executor UUID; mandatory for v3 lease issuance
	Epoch        int64
	PublicKey    ed25519.PublicKey
}

func (b Binding) Valid() bool {
	return validID(b.Target.NodeID) && validID(b.Target.ResourceID) &&
		len(b.Subscription) > 0 && len(b.Subscription) <= 1024 && b.Epoch > 0 &&
		(b.ExecutorID == "" || validID(b.ExecutorID)) &&
		len(b.PublicKey) == ed25519.PublicKeySize
}

func validID(s string) bool {
	id, err := uuid.Parse(s)
	return err == nil && id != uuid.Nil && id.String() == s
}

type Rates struct {
	Up       uint64
	Down     uint64
	Disabled bool
}

func (r Rates) Valid() bool {
	return r.Up > 0 && r.Down > 0 && r.Up <= 1<<40 && r.Down <= 1<<40
}

type Job struct {
	PublicKey  ed25519.PublicKey
	ResourceID string `json:",omitempty"`
	NodeID string
	ExecutorID string
	AuthorityGeneration uint64
	Operation  string
	Policy     corepolicy.Policy
	Challenge  string
}

type receipt struct {
	ResourceID string `json:",omitempty"`
	Operation  string
	Proof      []byte
}

type server struct {
	db    *sql.DB
	nodes map[string][]Binding
	bindingSource func() ([]Binding,error)
	leaseKey ed25519.PrivateKey
}

func (s *server) authorize(ctx context.Context) ([]Binding, error) {
	id, err := nodeidentity.FromGRPC(ctx)
	if err != nil {
		return nil,status.Error(codes.PermissionDenied,"verified node identity required")
	}
	if s.bindingSource!=nil {
		// Fail closed if the manifest was replaced with malformed or
		// inaccessible data. Never authorize from yesterday's cached map.
		current,err:=s.bindingSource()
		if err!=nil || ValidateBindings(current)!=nil {
			return nil,status.Error(codes.Unavailable,"trusted policy manifest unavailable")
		}
		bound:=make([]Binding,0)
		for _,b:=range current {
			if b.Target.NodeID==id {
				b.PublicKey=slices.Clone(b.PublicKey)
				bound=append(bound,b)
			}
		}
		if len(bound)==0{return nil,status.Error(codes.PermissionDenied,"node is not assigned")}
		return bound,nil
	}
	if len(s.nodes[id])==0 {
		return nil,status.Error(codes.PermissionDenied,"node is not assigned")
	}
	return s.nodes[id],nil
}

// ValidateBindings enforces one journal per local subscription and separates
// signing keys between nodes. A single core can sign for its own subscriptions.
func ValidateBindings(bindings []Binding) error {
	if len(bindings) == 0 {
		return errors.New("at least one policy binding is required")
	}
	targets := make(map[journal.Target]bool)
	subscriptions := make(map[[2]string]bool)
	nodeKeys := make(map[string][]byte)
	keyNodes := make(map[string]string)
	for _, b := range bindings {
		if !b.Valid() {
			return errors.New("invalid policy binding")
		}
		pair := [2]string{b.Target.NodeID, b.Subscription}
		if targets[b.Target] || subscriptions[pair] {
			return errors.New("duplicate node target or local subscription")
		}
		key := string(b.PublicKey)
		if node, ok := keyNodes[key]; ok && node != b.Target.NodeID {
			return errors.New("policy signing key belongs to another node")
		}
		if known := nodeKeys[b.Target.NodeID]; known != nil && !bytes.Equal(known, b.PublicKey) {
			return errors.New("node bindings require one core signing key")
		}
		targets[b.Target], subscriptions[pair] = true, true
		nodeKeys[b.Target.NodeID], keyNodes[key] = b.PublicKey, b.Target.NodeID
	}
	return nil
}

func (b Binding) job(cmd journal.Command) (Job, error) {
	var rates Rates
	if !validID(cmd.ID) || cmd.ExpectedRevision < 0 || cmd.ExpectedRevision > math.MaxInt64-2 ||
		json.Unmarshal(cmd.Payload, &rates) != nil || !rates.Valid() {
		return Job{}, status.Error(codes.FailedPrecondition, "invalid stored policy operation")
	}
	policy := corepolicy.Policy{ID: b.Subscription, Revision: uint64(cmd.ExpectedRevision + 2),
		UplinkBps: rates.Up, DownlinkBps: rates.Down, Disabled: rates.Disabled}
	challenge := sha256.Sum256(fmt.Appendf(nil, "elx-command-v1\n%s\n%s\n%s\n%d\n%x",
		b.Target.NodeID, b.Target.ResourceID, cmd.ID, b.Epoch, sha256.Sum256(cmd.Payload)))
	return Job{PublicKey: b.PublicKey, ResourceID: b.Target.ResourceID, NodeID:b.Target.NodeID,
		ExecutorID:b.ExecutorID, AuthorityGeneration:uint64(b.Epoch),
		Operation: cmd.ID, Policy: policy, Challenge: fmt.Sprintf("%x", challenge)}, nil
}

func (s *server) next(ctx context.Context, _ *emptypb.Empty) (*wrapperspb.BytesValue, error) {
	bindings, err := s.authorize(ctx)
	if err != nil {
		return nil, err
	}
	for _, b := range bindings {
		cmd, err := journal.Pending(ctx, s.db, b.Target)
		if errors.Is(err, sql.ErrNoRows) {
			continue
		}
		if err != nil {
			return nil, status.Error(codes.Unavailable, "journal unavailable")
		}
		job, err := b.job(cmd)
		if err != nil {
			return nil, err
		}
		data, err := json.Marshal(job)
		return wrapperspb.Bytes(data), err
	}
	return nil, status.Error(codes.NotFound, "no pending command")
}

func (s *server) confirm(ctx context.Context, in *wrapperspb.BytesValue) (*emptypb.Empty, error) {
	bindings, err := s.authorize(ctx)
	if err != nil {
		return nil, err
	}
	var ack receipt
	if len(in.GetValue()) > 1024 || json.Unmarshal(in.GetValue(), &ack) != nil || !validID(ack.Operation) ||
		len(ack.Proof) != ed25519.SignatureSize {
		return nil, status.Error(codes.InvalidArgument, "invalid policy receipt")
	}
	// Old single-target agents did not include a resource ID.
	if ack.ResourceID == "" && len(bindings) == 1 {
		ack.ResourceID = bindings[0].Target.ResourceID
	}
	index := slices.IndexFunc(bindings, func(b Binding) bool { return b.Target.ResourceID == ack.ResourceID })
	if index < 0 {
		return nil, status.Error(codes.PermissionDenied, "resource is not assigned to this node")
	}
	b := bindings[index]
	cmd, err := journal.Lookup(ctx, s.db, b.Target, ack.Operation)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, status.Error(codes.NotFound, "unknown command")
	}
	if err != nil {
		return nil, status.Error(codes.Unavailable, "journal unavailable")
	}
	job, err := b.job(cmd)
	if err != nil {
		return nil, err
	}
	if !corepolicy.VerifyProof(b.PublicKey, job.Challenge, job.Policy, ack.Proof) {
		return nil, status.Error(codes.PermissionDenied, "invalid durable policy signature")
	}
	err = journal.ConfirmApplied(ctx, s.db, b.Target, cmd.ID, cmd.ExpectedRevision+1, sha256.Sum256(cmd.Payload))
	switch {
	case errors.Is(err, journal.ErrRevision), errors.Is(err, journal.ErrReceipt):
		return nil, status.Error(codes.FailedPrecondition, "receipt conflicts with journal")
	case err != nil:
		return nil, status.Error(codes.Unavailable, "journal unavailable")
	}
	return &emptypb.Empty{}, nil
}

type service interface {
	next(context.Context, *emptypb.Empty) (*wrapperspb.BytesValue, error)
	confirm(context.Context, *wrapperspb.BytesValue) (*emptypb.Empty, error)
	lease(context.Context, *wrapperspb.BytesValue) (*wrapperspb.BytesValue, error)
	nextRateBarrier(context.Context, *emptypb.Empty) (*wrapperspb.BytesValue, error)
	confirmRateBarrier(context.Context, *wrapperspb.BytesValue) (*emptypb.Empty, error)
}

// Register installs policy delivery for provisioned node bindings. Callers must configure
// dedicated client CA verification on the gRPC server.
func Register(g *grpc.Server, db *sql.DB, bindings ...Binding) error {
	return register(g,db,nil,bindings...)
}

// RegisterWithSource reloads the trusted, validated manifest before every
// authenticated node command, so provisioning a new subscription does not
// require restarting the master. The callback must read only operator-owned
// files; a parse/permission error blocks new leases and policy jobs.
func RegisterWithSource(g *grpc.Server,db *sql.DB,source func()([]Binding,error))error{
	if source==nil{return errors.New("policy binding source required")}
	initial,err:=source()
	if err!=nil{return err}
	return register(g,db,source,initial...)
}

func register(g *grpc.Server, db *sql.DB, source func()([]Binding,error), bindings ...Binding) error {
	if g==nil || db == nil {
		return errors.New("policy journal database is required")
	}
	if err := ValidateBindings(bindings); err != nil {
		return err
	}
	leaseKey,err:=LoadLeaseKey()
	if err!=nil{return err}
	nodes := make(map[string][]Binding)
	for _, b := range bindings {
		b.PublicKey = slices.Clone(b.PublicKey)
		nodes[b.Target.NodeID] = append(nodes[b.Target.NodeID], b)
	}
	g.RegisterService(&grpc.ServiceDesc{
		ServiceName: serviceName, HandlerType: (*service)(nil),
		Methods: []grpc.MethodDesc{
			{MethodName: "Next", Handler: handler("Next", (*server).next)},
			{MethodName: "Confirm", Handler: handler("Confirm", (*server).confirm)},
			{MethodName: "Lease", Handler: handler("Lease", (*server).lease)},
			{MethodName: "RateBarrierNext", Handler: handler("RateBarrierNext", (*server).nextRateBarrier)},
			{MethodName: "RateBarrierConfirm", Handler: handler("RateBarrierConfirm", (*server).confirmRateBarrier)},
		},
	}, &server{db: db, nodes: nodes, bindingSource:source, leaseKey:leaseKey})
	return nil
}

func handler[Request, Response any](method string, call func(*server, context.Context, *Request) (*Response, error)) grpc.MethodHandler {
	return func(s any, ctx context.Context, decode func(any) error, intercept grpc.UnaryServerInterceptor) (any, error) {
		in := new(Request)
		if err := decode(in); err != nil {
			return nil, err
		}
		if intercept == nil {
			return call(s.(*server), ctx, in)
		}
		return intercept(ctx, in, &grpc.UnaryServerInfo{Server: s, FullMethod: "/" + serviceName + "/" + method},
			func(ctx context.Context, req any) (any, error) { return call(s.(*server), ctx, req.(*Request)) })
	}
}

type Applier interface {
	ApplyWithProof(context.Context, corepolicy.Policy, string, ed25519.PublicKey) ([]byte, error)
}

type ManagedApplier interface {
	ApplyManagedWithProof(context.Context, corepolicy.Policy, string, ed25519.PublicKey, corepolicy.ManagedOperation) ([]byte, error)
}

// ApplyNext pulls one command, applies it locally and sends its core proof.
func ApplyNext(ctx context.Context, conn grpc.ClientConnInterface, core Applier) error {
	var data wrapperspb.BytesValue
	if err := conn.Invoke(ctx, "/"+serviceName+"/Next", &emptypb.Empty{}, &data); err != nil {
		return err
	}
	var job Job
	if err := json.Unmarshal(data.Value, &job); err != nil {
		return err
	}
	var proof []byte
	if job.ExecutorID != "" {
		// When v3 manifest assigns a concrete executor, neither agent nor
		// library may downgrade the job to the legacy operation-less RPC.
		managed, ok := core.(ManagedApplier)
		if !ok || !validID(job.NodeID) || !validID(job.ExecutorID) || !validID(job.ResourceID) ||
			!validID(job.Operation) || job.AuthorityGeneration == 0 {
			return status.Error(codes.FailedPrecondition, "managed journal adapter unavailable or unbound")
		}
		proof, err = managed.ApplyManagedWithProof(ctx, job.Policy, job.Challenge, job.PublicKey, corepolicy.ManagedOperation{
			OperationID: job.Operation, NodeID: job.NodeID, ResourceID: job.ResourceID,
			ExecutorID: job.ExecutorID, AuthorityGeneration: job.AuthorityGeneration,
		})
	} else {
		proof, err = core.ApplyWithProof(ctx, job.Policy, job.Challenge, job.PublicKey)
	}
	if err != nil {
		return err
	}
	payload, err := json.Marshal(receipt{ResourceID: job.ResourceID, Operation: job.Operation, Proof: proof})
	if err != nil {
		return err
	}
	return conn.Invoke(ctx, "/"+serviceName+"/Confirm", wrapperspb.Bytes(payload), &emptypb.Empty{})
}
