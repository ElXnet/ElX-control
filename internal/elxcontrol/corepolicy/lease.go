package corepolicy

import (
	"context"
	"errors"
	"github.com/google/uuid"
	"google.golang.org/grpc/metadata"
	wire "github.com/ElXnet/ElX-control/internal/elxcontrol/corepolicy/wire"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/emptypb"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// RenewControlLease gives opaque, signed Control evidence to the local core.
// Only ElXray validates the pinned Control signing key and absolute expiry.
func (c *Client) RenewControlLease(ctx context.Context, ticket []byte) error {
	if c==nil || c.conn==nil || len(ticket)==0 || len(ticket)>2048 {
		return errors.New("invalid signed Control lease")
	}
	ctx,cancel:=context.WithTimeout(ctx,5*time.Second)
	defer cancel()
	return c.conn.Invoke(ctx,"/xray.app.policy.command.ControlLease/Renew",
		wrapperspb.Bytes(ticket),&emptypb.Empty{},grpc.MaxCallRecvMsgSize(1024))
}

// ManagedWitnessNonce obtains the current random per-boot nonce from the
// authenticated Unix-socket core. It is NOT cached across reconnect/reboot.
func (c *Client) ManagedWitnessNonce(ctx context.Context, subscription string)(string,error){
 if c==nil||c.conn==nil||subscription==""{return "",errors.New("invalid managed witness nonce request")}
 ctx,cancel:=context.WithTimeout(ctx,5*time.Second);defer cancel()
 ctx=metadata.AppendToOutgoingContext(ctx,"elx-store-witness-nonce","1")
 var head metadata.MD
 _,err:=c.rpc.GetSubscription(ctx,&wire.GetSubscriptionRequest{Id:subscription},grpc.Header(&head))
 if err!=nil{return "",err}
 values:=head.Get("elx-store-witness-nonce")
 if len(values)!=1{return "",errors.New("missing current core boot nonce")}
 id,e:=uuid.Parse(values[0])
 if e!=nil||id==uuid.Nil||id.String()!=values[0]{return "",errors.New("invalid core boot nonce")}
 return values[0],nil
}

// RenewControlLeaseWithWitness transports independently signed PostgreSQL
// HWM evidence alongside an unmodified Control-signed lease.
func (c *Client) RenewControlLeaseWithWitness(ctx context.Context,ticket,witness []byte)error{
 if c==nil||c.conn==nil||len(ticket)==0||len(ticket)>2048||
  len(witness)==0||len(witness)>2048{return errors.New("invalid signed lease/store witness")}
 ctx,cancel:=context.WithTimeout(ctx,5*time.Second);defer cancel()
 ctx=metadata.AppendToOutgoingContext(ctx,"elx-store-witness-bin",string(witness))
 return c.conn.Invoke(ctx,"/xray.app.policy.command.ControlLease/Renew",
  wrapperspb.Bytes(ticket),&emptypb.Empty{},grpc.MaxCallRecvMsgSize(1024))
}
