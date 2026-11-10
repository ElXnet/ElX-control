package policytransport

import (
	"context"
	"encoding/json"
	"errors"
	"os"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type LeaseCore interface {
	RenewControlLease(context.Context,[]byte) error
}

// A journal-managed core must use a fresh Control witness pinned to the
// current core boot nonce. An old lease alone cannot authorize recovery.
type LeaseCoreWithWitness interface {
	ManagedWitnessNonce(context.Context,string)(string,error)
	RenewControlLeaseWithWitness(context.Context,[]byte,[]byte) error
}

// ApplyLease asks Control to sign a new short-lived permission and forwards it
// unchanged to ElXray. Without a fresh mTLS response, the core gate expires.
func ApplyLease(ctx context.Context,conn grpc.ClientConnInterface,core LeaseCore,b Binding)error{
	if conn==nil||core==nil||!b.Valid(){return errors.New("signed lease requires a provisioned binding")}
	request,err:=json.Marshal(LeaseRequest{ResourceID:b.Target.ResourceID,Subscription:b.Subscription})
	if err!=nil{return err}
	var answer wrapperspb.BytesValue
	err=conn.Invoke(ctx,"/"+serviceName+"/Lease",wrapperspb.Bytes(request),&answer)
	if err!=nil{return err}
	if len(answer.Value)==0||len(answer.Value)>2048{return errors.New("invalid signed lease response")}
	if os.Getenv("ELX_AGENT_STORE_WITNESS_REQUIRED") != "1" {
		return core.RenewControlLease(ctx,answer.Value)
	}
	managed,ok:=core.(LeaseCoreWithWitness)
	if !ok {return errors.New("journal-managed core lacks independent HWM interface")}
	nonce,err:=managed.ManagedWitnessNonce(ctx,b.Subscription)
	if err!=nil{return err}
	witnessRequest,err:=json.Marshal(WitnessRequest{ResourceID:b.Target.ResourceID,
		Subscription:b.Subscription,Nonce:nonce})
	if err!=nil{return err}
	var proof wrapperspb.BytesValue
	if err:=conn.Invoke(ctx,"/"+serviceName+"/StoreWitness",
		wrapperspb.Bytes(witnessRequest),&proof);err!=nil{return err}
	if len(proof.Value)==0||len(proof.Value)>2048 {
		return errors.New("Control did not issue a signed independent store HWM")
	}
	return managed.RenewControlLeaseWithWitness(ctx,answer.Value,proof.Value)
}
