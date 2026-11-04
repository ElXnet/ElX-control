package fencetransport

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/url"
	"testing"

	"github.com/google/uuid"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/session"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

func verifiedFenceContext(node uuid.UUID) context.Context {
	uri,_:=url.Parse("spiffe://elxnet/node/"+node.String())
	leaf:=&x509.Certificate{URIs:[]*url.URL{uri}}
	state:=tls.ConnectionState{VerifiedChains:[][]*x509.Certificate{{leaf}},
		PeerCertificates:[]*x509.Certificate{leaf}}
	return peer.NewContext(context.Background(),&peer.Peer{
		AuthInfo:credentials.TLSInfo{State:state},
	})
}

func TestFenceTransportRejectsMissingIdentityAndWrongNode(t *testing.T) {
	server:=&receiver{}
	f:=session.Fence{OwnerID:uuid.New(),Generation:1,NodeID:uuid.New(),Incarnation:uuid.New()}
	raw,err:=json.Marshal(Receipt{Fence:f,Signature:make([]byte,64)})
	if err!=nil {t.Fatal(err)}
	_,err=server.submit(context.Background(),wrapperspb.Bytes(raw))
	if status.Code(err)!=codes.PermissionDenied {
		t.Fatalf("unverified gRPC peer passed fence boundary: %v",err)
	}
	_,err=server.submit(verifiedFenceContext(uuid.New()),wrapperspb.Bytes(raw))
	if status.Code(err)!=codes.PermissionDenied {
		t.Fatalf("foreign mTLS identity passed fence boundary: %v",err)
	}
}

func TestFenceRegisterNeedsDatabaseAndServer(t *testing.T) {
	if err:=Register(grpc.NewServer(),nil);err==nil {
		t.Fatal("session fence accepted missing durable journal")
	}
	if err:=Send(context.Background(),nil,session.Fence{},nil);err==nil {
		t.Fatal("client accepted unsigned session fence")
	}
}
