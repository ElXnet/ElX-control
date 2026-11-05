// Package nodeidentity extracts ElX node identities from verified mTLS peers.
package nodeidentity

import (
	"context"
	"crypto/tls"
	"errors"

	"github.com/google/uuid"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"
)

var ErrUnverified = errors.New("verified ElX node certificate required")

// FromGRPC requires a dedicated node CA on the receiving listener. The leaf
// must contain exactly one URI SAN in the form spiffe://elxnet/node/<uuid>.
func FromGRPC(ctx context.Context) (string, error) {
	p, ok := peer.FromContext(ctx)
	if !ok || p == nil {
		return "", ErrUnverified
	}
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return "", ErrUnverified
	}
	return fromTLS(info.State)
}

func fromTLS(state tls.ConnectionState) (string, error) {
	if len(state.VerifiedChains) == 0 || len(state.VerifiedChains[0]) == 0 {
		return "", ErrUnverified
	}
	leaf := state.VerifiedChains[0][0]
	if leaf == nil || len(leaf.URIs) != 1 || leaf.URIs[0] == nil {
		return "", ErrUnverified
	}
	uri := leaf.URIs[0]
	const prefix = "/node/"
	if uri.Scheme != "spiffe" || uri.Host != "elxnet" || uri.User != nil ||
		uri.RawQuery != "" || uri.ForceQuery || uri.Fragment != "" || uri.RawPath != "" || uri.Opaque != "" ||
		len(uri.Path) != len(prefix)+36 || uri.Path[:len(prefix)] != prefix {
		return "", ErrUnverified
	}
	id, err := uuid.Parse(uri.Path[len(prefix):])
	if err != nil || id == uuid.Nil || id.String() != uri.Path[len(prefix):] {
		return "", ErrUnverified
	}
	return id.String(), nil
}
