package nodeidentity

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"net/url"
	"testing"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

func TestGRPCIdentityRequiresVerifiedNodeSAN(t *testing.T) {
	const id = "00000000-0000-0000-0000-000000000001"
	node, _ := url.Parse("spiffe://elxnet/node/" + id)
	other, _ := url.Parse("spiffe://elxnet/admin/" + id)
	for _, tc := range []struct {
		name     string
		uris     []*url.URL
		verified bool
		want     string
	}{
		{"valid", []*url.URL{node}, true, id},
		{"unverified", []*url.URL{node}, false, ""},
		{"wrong role", []*url.URL{other}, true, ""},
		{"ambiguous", []*url.URL{node, other}, true, ""},
		{"no SAN", nil, true, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			leaf := &x509.Certificate{URIs: tc.uris}
			state := tls.ConnectionState{PeerCertificates: []*x509.Certificate{leaf}}
			if tc.verified {
				state.VerifiedChains = [][]*x509.Certificate{{leaf}}
			}
			ctx := peer.NewContext(context.Background(), &peer.Peer{AuthInfo: credentials.TLSInfo{State: state}})
			got, err := FromGRPC(ctx)
			if got != tc.want || (err == nil) != (tc.want != "") {
				t.Fatalf("identity = %q, error = %v", got, err)
			}
		})
	}
}
