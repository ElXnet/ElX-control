package corepolicy

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/google/uuid"
)

// AppliedEvidence is the JSON transport envelope for ElXray's exact signed
// durable operation transcript. Only the pinned core key is authoritative.
type AppliedEvidence struct {
	Version uint32 `json:"version"`
	OperationID string `json:"operationId"`
	PayloadSHA256 string `json:"payloadSha256"`
	NodeID string `json:"nodeId"`
	ExecutorID string `json:"executorId"`
	ResourceID string `json:"resourceId"`
	AuthorityGeneration uint64 `json:"authorityGeneration"`
	Revision uint64 `json:"revision"`
	CoreIncarnation string `json:"coreIncarnation"`
	StoreID string `json:"storeId"`
	CompletedUnixNanos int64 `json:"completedUnixNanos"`
	Signature []byte `json:"signature"`
}

func ManagedMutationDigest(p Policy) string {
	if p.Revision == 0 { return "" }
	transcript := fmt.Appendf(nil, "elx-managed-update-v1\n%s\n%d\n%d\n%d\n%d\n%t",
		p.ID,p.Revision-1,p.Revision,p.UplinkBps,p.DownlinkBps,p.Disabled)
	digest := sha256.Sum256(transcript)
	return hex.EncodeToString(digest[:])
}

func validCanonicalUUID(id string) bool {
	parsed,err:=uuid.Parse(id)
	return err==nil && parsed!=uuid.Nil && parsed.String()==id
}

// VerifyAppliedEvidence binds the committed operation, exact payload, active
// resource executor and epoch, core incarnation and durable store ID. A
// successful policy-only readback cannot substitute for this receipt.
func VerifyAppliedEvidence(publicKey ed25519.PublicKey, challenge string,
	operation ManagedOperation, policy Policy, raw []byte) bool {
	if len(publicKey)!=ed25519.PublicKeySize || len(raw)==0 || len(raw)>4096 ||
		challenge=="" || len(challenge)>128 { return false }
	var r AppliedEvidence
	dec:=json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	if dec.Decode(&r)!=nil {return false}
	if r.Version!=1 || r.OperationID!=operation.OperationID ||
		r.PayloadSHA256!=ManagedMutationDigest(policy) ||
		r.NodeID!=operation.NodeID || r.ExecutorID!=operation.ExecutorID ||
		r.ResourceID!=operation.ResourceID ||
		r.AuthorityGeneration!=operation.AuthorityGeneration ||
		r.Revision!=policy.Revision || r.CompletedUnixNanos<=0 ||
		!validCanonicalUUID(r.CoreIncarnation)||!validCanonicalUUID(r.StoreID) ||
		len(r.Signature)!=ed25519.SignatureSize {return false}
	message:=fmt.Appendf(nil,"elx-applied-operation-v1\n%x\n%s\n%s\n%s\n%s\n%s\n%d\n%d\n%s\n%s\n%d",
		challenge,r.OperationID,r.PayloadSHA256,r.NodeID,r.ExecutorID,r.ResourceID,
		r.AuthorityGeneration,r.Revision,r.CoreIncarnation,r.StoreID,r.CompletedUnixNanos)
	return ed25519.Verify(publicKey,message,r.Signature)
}
