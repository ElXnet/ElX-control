package corepolicy

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

// RateBarrierRequest is identical to ElXray's local rate-barrier RPC contract.
type RateBarrierRequest struct {
	EntitlementID uuid.UUID
	NodeID uuid.UUID
	ResourceID uuid.UUID
	OperationID uuid.UUID
	Subscription string
	Epoch int64
	Revision int64
	Up int64
	Down int64
}

func BarrierTranscript(r RateBarrierRequest) []byte {
	return fmt.Appendf(nil,"elx-rate-barrier-v1\n%s\n%s\n%s\n%s\n%d\n%d\n%d\n%d",
		r.EntitlementID,r.NodeID,r.ResourceID,r.OperationID,r.Epoch,r.Revision,r.Up,r.Down)
}

// ProveRateBarrier only returns when local ElXray has denied new admissions,
// closed all flows that could carry the previous higher rate and signed its
// exact durable rate revision. A normal policy ACK is not enough.
func (c *Client) ProveRateBarrier(ctx context.Context, r RateBarrierRequest,
	pinned ed25519.PublicKey) ([]byte,error) {
	if c==nil || c.conn==nil || len(pinned)!=ed25519.PublicKeySize ||
		r.EntitlementID==uuid.Nil||r.NodeID==uuid.Nil||r.ResourceID==uuid.Nil||
		r.OperationID==uuid.Nil||r.Epoch<=0||r.Revision<=0 {
		return nil,errors.New("invalid core rate barrier assignment")
	}
	raw,err:=json.Marshal(r)
	if err!=nil{return nil,err}
	ctx,cancel:=context.WithTimeout(ctx,40*time.Second)
	defer cancel()
	var proof wrapperspb.BytesValue
	if err:=c.conn.Invoke(ctx,"/xray.app.policy.command.RateBarrier/Prove",
		wrapperspb.Bytes(raw),&proof,grpc.MaxCallRecvMsgSize(1024));err!=nil {
		return nil,err
	}
	if len(proof.Value)!=ed25519.SignatureSize ||
		!ed25519.Verify(pinned,BarrierTranscript(r),proof.Value) {
		return nil,errors.New("untrusted ElXray rate-reduction barrier")
	}
	return proof.Value,nil
}
