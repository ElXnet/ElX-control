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
	ProfileID           string
	OperationID         string
	NodeID              string
	ResourceID          string
	ExecutorID          string
	SubscriptionID      string
	Email               string
	InboundTag          string
	ProfileGeneration   uint64
	AuthorityGeneration uint64
	PolicyRevision      uint64
	TranscriptSHA256    string
	InstallOperationID  string
	InstallTranscriptSHA256 string
	Flow                string
	Phase               string
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
		(prepared.Phase != "PREPARED" && prepared.Phase != "INSTALLED") {
		return TechnicalPrepared{}, errors.New("inconsistent non-authorizing technical profile readback")
	}
	return prepared, nil
}
