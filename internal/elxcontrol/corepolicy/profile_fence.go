package corepolicy

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/ElXnet/ElX-control/internal/elxcontrol/session"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// DrainProfile asks LOCAL ElXray to durably deny the authenticated VLESS UUID,
// close all its tracked flows and sign the generation-fenced receipt. The node
// supervisor verifies the pinned public key before relaying proof to Control.
func (c *Client) DrainProfile(ctx context.Context, fence session.Fence, pinned ed25519.PublicKey) ([]byte,error) {
	if c==nil || c.conn==nil || fence.OwnerID==uuid.Nil || fence.ProfileID==uuid.Nil ||
		fence.NodeID==uuid.Nil || fence.Incarnation==uuid.Nil || fence.Generation<=0 ||
		len(pinned)!=ed25519.PublicKeySize {
		return nil,errors.New("invalid VLESS profile fence source")
	}
	data,err:=json.Marshal(fence)
	if err!=nil {return nil,err}
	ctx,cancel:=context.WithTimeout(ctx,35*time.Second)
	defer cancel()
	var response wrapperspb.BytesValue
	if err:=c.conn.Invoke(ctx,
		"/xray.app.policy.command.ProfileFence/Drain",
		wrapperspb.Bytes(data),&response,grpc.MaxCallRecvMsgSize(1024));err!=nil {
		return nil,fmt.Errorf("local ElXray profile drain: %w",err)
	}
	signature:=response.GetValue()
	if len(signature)!=ed25519.SignatureSize ||
		!ed25519.Verify(pinned,session.FenceTranscript(fence),signature) {
		return nil,errors.New("core profile fence signature did not match provisioned key")
	}
	return signature,nil
}
