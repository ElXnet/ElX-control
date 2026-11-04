package corepolicy

import (
	"context"
	"net"
	"sync/atomic"
	"testing"

	wire "github.com/ElXnet/ElX-control/internal/elxcontrol/corepolicy/wire"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

type policyServer struct {
	wire.UnimplementedSubscriptionServiceServer
	writes atomic.Int32
}

func (s *policyServer) SetSubscription(_ context.Context, req *wire.SetSubscriptionRequest) (*wire.Subscription, error) {
	s.writes.Add(1)
	return &wire.Subscription{Id: req.Id, Revision: req.Revision}, nil
}

func (*policyServer) GetSubscription(context.Context, *wire.GetSubscriptionRequest) (*wire.Subscription, error) {
	return &wire.Subscription{Id: "test", Revision: 2, UplinkBps: 100, DownlinkBps: 200}, nil
}

func TestApplyVerifiesLiveState(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	core := new(policyServer)
	wire.RegisterSubscriptionServiceServer(server, core)
	go server.Serve(listener)
	t.Cleanup(server.Stop)
	conn, err := grpc.NewClient(listener.Addr().String(), grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		t.Fatal(err)
	}
	client := &Client{conn: conn, rpc: wire.NewSubscriptionServiceClient(conn)}
	t.Cleanup(func() { client.Close() })
	desired := Policy{ID: "test", Revision: 2, UplinkBps: 100, DownlinkBps: 200}
	if _, err := client.ApplyWithProof(context.Background(), desired, "op", make([]byte, 32)); err == nil || core.writes.Load() != 0 {
		t.Fatal("non-durable core accepted managed apply")
	}
	if err := client.Apply(context.Background(), desired); err != nil {
		t.Fatal(err)
	}
	desired.DownlinkBps++
	if err := client.Apply(context.Background(), desired); err == nil {
		t.Fatal("accepted mismatched readback")
	}
	desired.DownlinkBps = 0
	if err := (*Client)(nil).Apply(context.Background(), desired); err == nil {
		t.Fatal("accepted unlimited rate")
	}
}
