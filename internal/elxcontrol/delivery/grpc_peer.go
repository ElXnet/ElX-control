package delivery

import (
	"context"

	"github.com/ElXnet/ElX-control/internal/elxcontrol/journal"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/nodeidentity"
)

// NextFromPeer derives the node ID from the verified transport certificate.
func (s *Service) NextFromPeer(ctx context.Context, resourceID string) (Command, error) {
	nodeID, err := nodeidentity.FromGRPC(ctx)
	if err != nil {
		return Command{}, ErrUnauthorized
	}
	return s.Next(ctx, nodeID, journal.Target{NodeID: nodeID, ResourceID: resourceID})
}

// ConfirmFromPeer binds the receipt to the authenticated transport identity.
func (s *Service) ConfirmFromPeer(ctx context.Context, receipt AppliedReceipt) error {
	nodeID, err := nodeidentity.FromGRPC(ctx)
	if err != nil {
		return ErrUnauthorized
	}
	return s.Confirm(ctx, nodeID, receipt)
}
