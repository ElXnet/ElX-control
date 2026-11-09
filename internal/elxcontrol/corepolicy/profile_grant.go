package corepolicy

import (
	"fmt"

	"github.com/google/uuid"
)

// ProfileGrantIntent is the canonical body that Control must persist and
// reserve before signing. A transcript generator by itself grants NOTHING:
// the signer is a privileged Control journal workflow, not this package.
type ProfileGrantIntent struct {
	Version             uint32
	Action              string
	OperationID         uuid.UUID
	NodeID              uuid.UUID
	ExecutorID          uuid.UUID
	ResourceID          uuid.UUID
	ProfileID           uuid.UUID
	SubscriptionID      string
	Email               string
	InboundTag          string
	ProfileGeneration   uint64
	AuthorityGeneration uint64
	PolicyRevision      uint64
	NotBefore           int64
	NotAfter            int64
}

func (g ProfileGrantIntent) Transcript() []byte {
	if g.Version!=1 {return nil}
	return fmt.Appendf(nil,"elx-profile-grant-v1\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%d\n%d\n%d\n%d\n%d",
		g.Action,g.OperationID,g.NodeID,g.ExecutorID,g.ResourceID,
		g.ProfileID,g.SubscriptionID,g.Email,g.InboundTag,"vless",
		g.ProfileGeneration,g.AuthorityGeneration,g.PolicyRevision,g.NotBefore,g.NotAfter)
}
