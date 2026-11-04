package corepolicy

import (
	"context"
	"errors"
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
