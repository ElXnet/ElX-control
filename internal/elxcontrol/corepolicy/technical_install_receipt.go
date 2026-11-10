package corepolicy

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"strconv"
	"strings"

	"github.com/google/uuid"
)

var ErrInstallProof = errors.New("missing, forged or wrongly scoped core VLESS installed proof")

// InstallReceipt is signed by the running ElXray incarnation, not by Control
// and never by the node agent. It is not a device/owner admission receipt.
type InstallReceipt struct {
	Version             uint32
	OperationID         uuid.UUID
	ProfileID           uuid.UUID
	NodeID              uuid.UUID
	ExecutorID          uuid.UUID
	ResourceID          uuid.UUID
	StoreID             uuid.UUID
	CoreIncarnation     uuid.UUID
	AuthorityGeneration uint64
	PolicyRevision      uint64
	TranscriptSHA256    string
	Signature           []byte
}

func (p InstallReceipt) Transcript() []byte {
	return []byte(strings.Join([]string{
		"elx-vless-installed-proof-v1", p.OperationID.String(),
		p.ProfileID.String(), p.NodeID.String(), p.ExecutorID.String(),
		p.ResourceID.String(), p.StoreID.String(), p.CoreIncarnation.String(),
		strconv.FormatUint(p.AuthorityGeneration, 10),
		strconv.FormatUint(p.PolicyRevision, 10), p.TranscriptSHA256,
	}, "\n"))
}

// VerifyInstallReceipt must use Control's independently pinned core key and
// durable store/incarnation witness, never values selected by the agent.
// An authentic receipt can only complete its own pending operation; it does
// not itself authorize a VPN user session or free an occupied slot.
func VerifyInstallReceipt(p InstallReceipt, grant ProfileGrantIntent,
	pinnedKey ed25519.PublicKey, expectedStoreID, expectedIncarnation uuid.UUID,
) error {
	if p.Version != 1 || grant.Version != 2 || grant.Action != "install" ||
		grant.ProfileID == uuid.Nil || p.StoreID == uuid.Nil ||
		p.CoreIncarnation == uuid.Nil || expectedStoreID == uuid.Nil ||
		expectedIncarnation == uuid.Nil || p.StoreID != expectedStoreID ||
		p.CoreIncarnation != expectedIncarnation ||
		p.NodeID != grant.NodeID || p.ExecutorID != grant.ExecutorID ||
		p.ResourceID != grant.ResourceID || p.ProfileID != grant.ProfileID ||
		p.OperationID != grant.OperationID ||
		p.AuthorityGeneration != grant.AuthorityGeneration ||
		p.PolicyRevision != grant.PolicyRevision ||
		len(pinnedKey) != ed25519.PublicKeySize ||
		len(p.Signature) != ed25519.SignatureSize {
		return ErrInstallProof
	}
	hash := sha256.Sum256(grant.Transcript())
	if p.TranscriptSHA256 != hex.EncodeToString(hash[:]) ||
		!ed25519.Verify(pinnedKey, p.Transcript(), p.Signature) {
		return ErrInstallProof
	}
	return nil
}
