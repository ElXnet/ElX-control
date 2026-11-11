package corepolicy

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

const technicalProfileService = "/elx.core.v1.TechnicalProfile/"

// TechnicalPrepared proves ONLY the local core persisted a signed
// preparation. The remote Control must NEVER turn this into an APPLIED
// installation receipt or a device/owner authorization.
type TechnicalPrepared struct {
	ProfileID               string
	OperationID             string
	NodeID                  string
	ResourceID              string
	ExecutorID              string
	SubscriptionID          string
	Email                   string
	InboundTag              string
	ProfileGeneration       uint64
	AuthorityGeneration     uint64
	PolicyRevision          uint64
	TranscriptSHA256        string
	InstallOperationID      string
	InstallTranscriptSHA256 string
	Flow                    string
	RetireOperationID       string
	RetireTranscriptSHA256  string
	RetireGeneration        uint64
	Phase                   string
}

// PrepareTechnicalProfile forwards the exact Control signed JSON unchanged.
// The core independently checks the pinned key, lease and OS peer identity.
func (c *Client) PrepareTechnicalProfile(ctx context.Context, job []byte) (TechnicalPrepared, error) {
	if c == nil || c.conn == nil || len(job) == 0 || len(job) > 4096 {
		return TechnicalPrepared{}, errors.New("missing or oversized signed technical profile job")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var response wrapperspb.BytesValue
	if err := c.conn.Invoke(ctx, technicalProfileService+"Prepare",
		wrapperspb.Bytes(job), &response, grpc.MaxCallRecvMsgSize(4096)); err != nil {
		return TechnicalPrepared{}, err
	}
	if len(response.Value) == 0 || len(response.Value) > 4096 {
		return TechnicalPrepared{}, errors.New("invalid prepared profile readback size")
	}
	var prepared TechnicalPrepared
	if err := json.Unmarshal(response.Value, &prepared); err != nil {
		return TechnicalPrepared{}, err
	}
	profile, err := uuid.Parse(prepared.ProfileID)
	if err != nil || profile == uuid.Nil || profile.String() != prepared.ProfileID ||
		prepared.Phase != "PREPARED" {
		return TechnicalPrepared{}, errors.New("core did not durably prepare the requested VLESS profile")
	}
	return prepared, nil
}

// InstallTechnicalProfile forwards a separately signed v2 INSTALL instruction.
// It does not convert a local technical readback into centrally authorized
// APPLIED, device admission, or session-owner release.
func (c *Client) InstallTechnicalProfile(ctx context.Context, job []byte) (TechnicalPrepared, error) {
	if c == nil || c.conn == nil || len(job) == 0 || len(job) > 4096 {
		return TechnicalPrepared{}, errors.New("missing or oversized signed install job")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var response wrapperspb.BytesValue
	if err := c.conn.Invoke(ctx, technicalProfileService+"Install",
		wrapperspb.Bytes(job), &response, grpc.MaxCallRecvMsgSize(4096)); err != nil {
		return TechnicalPrepared{}, err
	}
	if len(response.Value) == 0 || len(response.Value) > 4096 {
		return TechnicalPrepared{}, errors.New("invalid installed technical profile readback size")
	}
	var installed TechnicalPrepared
	if err := json.Unmarshal(response.Value, &installed); err != nil {
		return TechnicalPrepared{}, err
	}
	id, err := uuid.Parse(installed.ProfileID)
	if err != nil || id == uuid.Nil || id.String() != installed.ProfileID ||
		installed.Phase != "INSTALLED" || installed.InstallOperationID == "" {
		return TechnicalPrepared{}, errors.New("core did not verify live VLESS registration")
	}
	return installed, nil
}

// ReadTechnicalInstalledProof asks the running core to authenticate a
// Control-signed v2 INSTALL job and sign its live VLESS readback. The local
// agent is not permitted to mark Control APPLIED; the authoritative backend
// must verify this Ed25519 proof against its pinned store/incarnation.
func (c *Client) ReadTechnicalInstalledProof(ctx context.Context, job []byte) (InstallReceipt, error) {
	if c == nil || c.conn == nil || len(job) == 0 || len(job) > 4096 {
		return InstallReceipt{}, errors.New("missing or oversized signed technical install job")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var response wrapperspb.BytesValue
	if err := c.conn.Invoke(ctx, technicalProfileService+"InstalledProof",
		wrapperspb.Bytes(job), &response, grpc.MaxCallRecvMsgSize(4096)); err != nil {
		return InstallReceipt{}, err
	}
	if len(response.Value) == 0 || len(response.Value) > 4096 {
		return InstallReceipt{}, errors.New("invalid core-signed installed evidence size")
	}
	var proof InstallReceipt
	if err := json.Unmarshal(response.Value, &proof); err != nil {
		return InstallReceipt{}, err
	}
	if proof.Version != 1 || proof.OperationID == uuid.Nil ||
		proof.ProfileID == uuid.Nil || proof.StoreID == uuid.Nil ||
		proof.CoreIncarnation == uuid.Nil || len(proof.Signature) != 64 {
		return InstallReceipt{}, errors.New("missing required core-signed installed evidence")
	}
	return proof, nil
}

// RetireTechnicalProfile invokes only the protected, separately signed
// non-admitting VLESS Retire RPC, never the upstream mutable HandlerService.
func (c *Client) RetireTechnicalProfile(ctx context.Context, job []byte) (TechnicalPrepared, error) {
	if c == nil || c.conn == nil || len(job) == 0 || len(job) > 4096 {
		return TechnicalPrepared{}, errors.New("missing or oversized signed technical RETIRE job")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var response wrapperspb.BytesValue
	if err := c.conn.Invoke(ctx, technicalProfileService+"Retire",
		wrapperspb.Bytes(job), &response, grpc.MaxCallRecvMsgSize(4096)); err != nil {
		return TechnicalPrepared{}, err
	}
	if len(response.Value) == 0 || len(response.Value) > 4096 {
		return TechnicalPrepared{}, errors.New("invalid retired technical profile readback")
	}
	var retired TechnicalPrepared
	if err := json.Unmarshal(response.Value, &retired); err != nil {
		return TechnicalPrepared{}, err
	}
	if retired.Phase != "RETIRED" || retired.RetireOperationID == "" ||
		retired.RetireGeneration < 2 || retired.ProfileID == "" {
		return TechnicalPrepared{}, errors.New("core did not durably retire the effective VLESS UUID")
	}
	return retired, nil
}

// ReadTechnicalRetiredProof requests core-signed evidence for an exact
// Control-signed RETIRE and its observed absence in the real VLESS validator.
func (c *Client) ReadTechnicalRetiredProof(ctx context.Context, job []byte) (RetireReceipt, error) {
	if c == nil || c.conn == nil || len(job) == 0 || len(job) > 4096 {
		return RetireReceipt{}, errors.New("missing or oversized signed RETIRE job")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var response wrapperspb.BytesValue
	if err := c.conn.Invoke(ctx, technicalProfileService+"RetiredProof",
		wrapperspb.Bytes(job), &response, grpc.MaxCallRecvMsgSize(4096)); err != nil {
		return RetireReceipt{}, err
	}
	if len(response.Value) == 0 || len(response.Value) > 4096 {
		return RetireReceipt{}, errors.New("invalid signed retired proof size")
	}
	var proof RetireReceipt
	if err := json.Unmarshal(response.Value, &proof); err != nil {
		return RetireReceipt{}, err
	}
	if proof.Version != 1 || proof.OperationID == uuid.Nil ||
		proof.ProfileID == uuid.Nil || proof.StoreID == uuid.Nil ||
		proof.CoreIncarnation == uuid.Nil || proof.RetireGeneration < 2 ||
		len(proof.Signature) != 64 {
		return RetireReceipt{}, errors.New("invalid core-signed retired evidence")
	}
	return proof, nil
}

// ReadbackTechnicalProfile is read-only and must not be confused with signed
// proof of live VLESS AddUser application.
func (c *Client) ReadbackTechnicalProfile(ctx context.Context, profileID string) (TechnicalPrepared, error) {
	id, err := uuid.Parse(profileID)
	if c == nil || c.conn == nil || err != nil || id == uuid.Nil || id.String() != profileID {
		return TechnicalPrepared{}, errors.New("invalid technical profile readback identity")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var response wrapperspb.BytesValue
	if err := c.conn.Invoke(ctx, technicalProfileService+"Readback",
		wrapperspb.String(profileID), &response, grpc.MaxCallRecvMsgSize(4096)); err != nil {
		return TechnicalPrepared{}, err
	}
	if len(response.Value) == 0 || len(response.Value) > 4096 {
		return TechnicalPrepared{}, errors.New("invalid technical profile readback")
	}
	var prepared TechnicalPrepared
	if err := json.Unmarshal(response.Value, &prepared); err != nil {
		return TechnicalPrepared{}, err
	}
	if prepared.ProfileID != profileID ||
		(prepared.Phase != "PREPARED" && prepared.Phase != "INSTALLED" && prepared.Phase != "RETIRED") {
		return TechnicalPrepared{}, errors.New("inconsistent non-authorizing technical profile readback")
	}
	return prepared, nil
}
