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

// These operations only request proof of a previously completed, journaled
// technical mutation. They MUST NOT resend an expired INSTALL/RETIRE grant.
func (c *Client) ReadRecoveredTechnicalInstalledProof(ctx context.Context,
	profileID, operationID string) (InstallReceipt, error) {
	var proof InstallReceipt
	if err := c.recoveryTechnicalProof(ctx, profileID, operationID,
		"RecoverInstalledProof", &proof); err != nil {
		return InstallReceipt{}, err
	}
	if proof.Version != 1 || proof.ProfileID == uuid.Nil ||
		proof.OperationID == uuid.Nil || proof.ProfileID.String() != profileID ||
		proof.OperationID.String() != operationID || proof.StoreID == uuid.Nil ||
		proof.CoreIncarnation == uuid.Nil || len(proof.Signature) != 64 {
		return InstallReceipt{}, errors.New("invalid core signed installed recovery evidence")
	}
	return proof, nil
}

func (c *Client) ReadRecoveredTechnicalRetiredProof(ctx context.Context,
	profileID, operationID string) (RetireReceipt, error) {
	var proof RetireReceipt
	if err := c.recoveryTechnicalProof(ctx, profileID, operationID,
		"RecoverRetiredProof", &proof); err != nil {
		return RetireReceipt{}, err
	}
	if proof.Version != 1 || proof.ProfileID == uuid.Nil ||
		proof.OperationID == uuid.Nil || proof.ProfileID.String() != profileID ||
		proof.OperationID.String() != operationID || proof.StoreID == uuid.Nil ||
		proof.CoreIncarnation == uuid.Nil || proof.RetireGeneration != 2 ||
		len(proof.Signature) != 64 {
		return RetireReceipt{}, errors.New("invalid core signed retired recovery evidence")
	}
	return proof, nil
}

func (c *Client) recoveryTechnicalProof(ctx context.Context,
	profileID, operationID, method string, dest any) error {
	p, pErr := uuid.Parse(profileID)
	op, opErr := uuid.Parse(operationID)
	if c == nil || c.conn == nil || pErr != nil || opErr != nil ||
		p == uuid.Nil || op == uuid.Nil || p.String() != profileID ||
		op.String() != operationID {
		return errors.New("technical recovery requires canonical operation and profile IDs")
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()
	var result wrapperspb.BytesValue
	if err := c.conn.Invoke(ctx, technicalProfileService+method,
		wrapperspb.String(profileID+"/"+operationID), &result,
		grpc.MaxCallRecvMsgSize(4096)); err != nil {
		return err
	}
	if len(result.Value) == 0 || len(result.Value) > 4096 {
		return errors.New("invalid bounded core technical recovery proof")
	}
	return json.Unmarshal(result.Value, dest)
}
