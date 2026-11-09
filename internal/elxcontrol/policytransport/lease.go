package policytransport

import (
	"context"
	"bytes"
	"database/sql"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/journal"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// Lease v3 binds the same Control-signed budget to one node, resource,
// executor and persisted grant epoch. Legacy v2 is never issued here.
type Lease struct {
	Version             uint32
	NodeID              uuid.UUID
	ResourceID          uuid.UUID
	ExecutorID          uuid.UUID
	AuthorityGeneration uint64
	Subscription        string
	Sequence            int64
	NotBefore           int64
	NotAfter            int64
	CeilingUp           int64
	CeilingDown         int64
	Signature           []byte
}

func (t Lease) transcript() []byte {
	return fmt.Appendf(nil, "elx-control-lease-v3\n%s\n%s\n%s\n%s\n%d\n%d\n%d\n%d\n%d\n%d",
		t.NodeID, t.ResourceID, t.ExecutorID, t.Subscription,
		t.Sequence, t.NotBefore, t.NotAfter, t.CeilingUp, t.CeilingDown, t.AuthorityGeneration)
}
type LeaseRequest struct { ResourceID string; Subscription string }

// LoadLeaseKey only reads a dedicated private key on the master. A missing key
// disables leasing; nodes that require leases remain blocked, never unlimited.
func LoadLeaseKey() (ed25519.PrivateKey,error) {
	path:=os.Getenv("ELX_CONTROL_LEASE_SEED_FILE")
	if path=="" {return nil,nil}
	info,err:=os.Stat(path)
	if err!=nil {return nil,err}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0077!=0 {
		return nil,errors.New("Control lease signing seed must be a private regular file")
	}
	raw,err:=os.ReadFile(path)
	if err!=nil {return nil,err}
	seed,err:=hex.DecodeString(string(raw))
	if err!=nil||len(seed)!=ed25519.SeedSize {return nil,errors.New("invalid Control lease signing seed")}
	return ed25519.NewKeyFromSeed(seed),nil
}

// lease is a short-lived, node-specific authorization, NOT a rate policy
// update. The server must verify the active, enabled entitlement in PostgreSQL
// before signing; mTLS alone does not make an expired subscription eligible.
func (s *server) lease(ctx context.Context,in *wrapperspb.BytesValue)(*wrapperspb.BytesValue,error) {
	bindings,err:=s.authorize(ctx)
	if err!=nil{return nil,err}
	if len(s.leaseKey)!=ed25519.PrivateKeySize {
		return nil,status.Error(codes.FailedPrecondition,"Control lease issuer not configured")
	}
	if len(in.GetValue())==0||len(in.GetValue())>512 {
		return nil,status.Error(codes.InvalidArgument,"invalid lease request")
	}
	var req LeaseRequest
	if json.Unmarshal(in.GetValue(),&req)!=nil || !validID(req.ResourceID) || req.Subscription=="" {
		return nil,status.Error(codes.InvalidArgument,"invalid subscription lease binding")
	}
	var binding *Binding
	for i:=range bindings {
		if bindings[i].Target.ResourceID==req.ResourceID && bindings[i].Subscription==req.Subscription {
			binding=&bindings[i]
			break
		}
	}
	if binding==nil {
		return nil,status.Error(codes.PermissionDenied,"lease target not assigned to authenticated node")
	}
	// Executor identity is provisioned by the trusted Control manifest, never
	// accepted from the remote node's LeaseRequest JSON body.
	if !validID(binding.ExecutorID) {
		return nil,status.Error(codes.FailedPrecondition,"v3 lease executor binding is not provisioned")
	}
	var entitlement string
	var ceilingUp,ceilingDown,storedEpoch int64
	var pinnedKey []byte
	err=s.db.QueryRowContext(ctx,`SELECT g.entitlement_id::text,g.committed_up,g.committed_down,
		g.epoch,g.barrier_public_key
		FROM elx_rate_grants g
		JOIN elx_entitlements e ON e.id=g.entitlement_id
		WHERE g.node_id=$1 AND g.resource_id=$2 AND e.enabled=true
		  AND e.valid_until>clock_timestamp()
		  AND g.committed_up>0 AND g.committed_down>0
		  AND NOT EXISTS(SELECT 1 FROM elx_core_rotations rot
			 WHERE rot.node_id=g.node_id AND rot.state='quiescing')
		  AND (NOT EXISTS(SELECT 1 FROM elx_paid_profiles p
			 WHERE p.entitlement_id=e.id) OR
		       EXISTS(SELECT 1 FROM elx_paid_profiles p
			 WHERE p.entitlement_id=e.id AND p.status='active'))
		  AND (SELECT count(*) FROM elx_core_identities c
			WHERE c.node_id=g.node_id AND c.public_key=g.barrier_public_key
			  AND c.revoked=false)=1
	`,reqNodeID(binding.Target.NodeID),reqNodeID(req.ResourceID)).
		Scan(&entitlement,&ceilingUp,&ceilingDown,&storedEpoch,&pinnedKey)
	if errors.Is(err,sql.ErrNoRows){return nil,status.Error(codes.FailedPrecondition,"subscription not eligible for a Control lease")}
	if err!=nil {return nil,status.Error(codes.Unavailable,"subscription lease eligibility unavailable")}
	// A restarted or superseded Control policy service must never sign a
	// lease with a stale manifest. Rotate the pinned core key and epoch
	// atomically with rate-grant ownership, then restart the policy service.
	if storedEpoch!=binding.Epoch || !bytes.Equal(pinnedKey,binding.PublicKey){
		return nil,status.Error(codes.FailedPrecondition,"core policy binding superseded")
	}
	// A live FUP needs a recent signed usage sequence for every active
	// rate grant, including the exact subscription/resource requesting this
	// lease. Otherwise Control must not authorize continued unmetered VPN.
	ready,err:=journal.SignedFUPLeaseReady(ctx,s.db,entitlement,
		binding.Target.NodeID,binding.Target.ResourceID,req.Subscription)
	if err!=nil{return nil,status.Error(codes.Unavailable,"signed usage eligibility unavailable")}
	if !ready{return nil,status.Error(codes.FailedPrecondition,"signed FUP accounting is unavailable or stale")}
	now:=time.Now().UTC()
	node,err:=uuid.Parse(binding.Target.NodeID)
	if err!=nil {return nil,status.Error(codes.Internal,"invalid bound node UUID")}
	resource, err := uuid.Parse(binding.Target.ResourceID)
	if err != nil || resource == uuid.Nil {return nil,status.Error(codes.Internal,"invalid rate resource UUID")}
	executor, err := uuid.Parse(binding.ExecutorID)
	if err != nil || executor == uuid.Nil {return nil,status.Error(codes.Internal,"invalid core executor UUID")}
	if storedEpoch <= 0 {return nil,status.Error(codes.FailedPrecondition,"invalid durable grant generation")}
	t:=Lease{Version:3,NodeID:node,ResourceID:resource,ExecutorID:executor,
		AuthorityGeneration:uint64(storedEpoch),Subscription:req.Subscription,Sequence:now.UnixNano(),
		NotBefore:now.Unix(),NotAfter:now.Unix()+15,
		CeilingUp:ceilingUp,CeilingDown:ceilingDown}
	t.Signature=ed25519.Sign(s.leaseKey,t.transcript())
	payload,err:=json.Marshal(t)
	if err!=nil {return nil,status.Error(codes.Internal,"cannot encode lease")}
	return wrapperspb.Bytes(payload),nil
}

func reqNodeID(raw string) uuid.UUID {
	id,_:=uuid.Parse(raw)
	return id
}
