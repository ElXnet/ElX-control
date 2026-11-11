package corepolicy

import (
	"fmt"
	"strconv"
	"strings"

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
	Flow                string
	ProfileGeneration   uint64
	AuthorityGeneration uint64
	PolicyRevision      uint64
	NotBefore           int64
	NotAfter            int64
}

func (g ProfileGrantIntent) Transcript() []byte {
	if g.Version == 2 {
		return []byte(strings.Join([]string{
			"elx-profile-grant-v2", g.Action, g.OperationID.String(),
			g.NodeID.String(), g.ExecutorID.String(), g.ResourceID.String(),
			g.ProfileID.String(), g.SubscriptionID, g.Email, g.InboundTag,
			"vless", g.Flow,
			strconv.FormatUint(g.ProfileGeneration, 10),
			strconv.FormatUint(g.AuthorityGeneration, 10),
			strconv.FormatUint(g.PolicyRevision, 10),
			strconv.FormatInt(g.NotBefore, 10),
			strconv.FormatInt(g.NotAfter, 10),
		}, "\n"))
	}
	if g.Version != 1 {
		return nil
	}
	return fmt.Appendf(nil, "elx-profile-grant-v1\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%s\n%d\n%d\n%d\n%d\n%d",
		g.Action, g.OperationID, g.NodeID, g.ExecutorID, g.ResourceID,
		g.ProfileID, g.SubscriptionID, g.Email, g.InboundTag, "vless",
		g.ProfileGeneration, g.AuthorityGeneration, g.PolicyRevision, g.NotBefore, g.NotAfter)
}
