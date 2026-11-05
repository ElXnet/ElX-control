package policytransport

import (
	"context"
	"encoding/json"
	"errors"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type LeaseCore interface {
	RenewControlLease(context.Context,[]byte) error
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
	return core.RenewControlLease(ctx,answer.Value)
}
