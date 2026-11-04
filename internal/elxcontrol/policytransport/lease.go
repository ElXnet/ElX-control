package policytransport

import (
	"context"
	"crypto/ed25519"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type Lease struct {
	NodeID uuid.UUID
	Subscription string
	Sequence int64
	NotBefore int64
	NotAfter int64
	Signature []byte
}

func (t Lease) transcript() []byte {
	return fmt.Appendf(nil,"elx-control-lease-v1\n%s\n%s\n%d\n%d\n%d",
		t.NodeID,t.Subscription,t.Sequence,t.NotBefore,t.NotAfter)
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
	var eligible bool
	err=s.db.QueryRowContext(ctx,`SELECT EXISTS (
		SELECT 1 FROM elx_rate_grants g
		JOIN elx_entitlements e ON e.id=g.entitlement_id
		WHERE g.node_id=$1 AND g.resource_id=$2 AND e.enabled=true
		  AND e.valid_until>clock_timestamp() AND g.committed_up>0 AND g.committed_down>0
	)`,reqNodeID(binding.Target.NodeID),reqNodeID(req.ResourceID)).Scan(&eligible)
	if err!=nil {return nil,status.Error(codes.Unavailable,"subscription lease eligibility unavailable")}
	if !eligible {return nil,status.Error(codes.FailedPrecondition,"subscription not eligible for a Control lease")}
	now:=time.Now().UTC()
	node,err:=uuid.Parse(binding.Target.NodeID)
	if err!=nil {return nil,status.Error(codes.Internal,"invalid bound node UUID")}
	t:=Lease{NodeID:node,Subscription:req.Subscription,Sequence:now.UnixNano(),
		NotBefore:now.Unix(),NotAfter:now.Unix()+15}
	t.Signature=ed25519.Sign(s.leaseKey,t.transcript())
	payload,err:=json.Marshal(t)
	if err!=nil {return nil,status.Error(codes.Internal,"cannot encode lease")}
	return wrapperspb.Bytes(payload),nil
}

func reqNodeID(raw string) uuid.UUID {
	id,_:=uuid.Parse(raw)
	return id
}
