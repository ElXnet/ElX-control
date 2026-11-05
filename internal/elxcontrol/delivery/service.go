// Package delivery implements the Control-side command and receipt boundary.
package delivery

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"errors"

	"github.com/ElXnet/ElX-control/internal/elxcontrol/journal"
)

var (
	ErrUnauthorized = errors.New("node is not authorized for this resource")
	ErrReceipt      = errors.New("invalid applied receipt")
)

// Assignment is resolved from trusted Control state for the specific command.
// An assignment must be invalidated when its authority or executor changes.
type Assignment struct {
	Epoch       int64
	ExecutorID  string
	Incarnation string
}

type Command struct {
	journal.Command
	Target      journal.Target
	Assignment  Assignment
	PayloadHash [32]byte
}

type AppliedReceipt struct {
	Target              journal.Target
	OperationID         string
	Revision            int64
	Assignment          Assignment
	PayloadHash         [32]byte
	StateHash           [32]byte
	RestartManifestHash [32]byte
}

// Authority resolves the current assignment and verifies durable core evidence.
// Both methods must fail closed if the authority or runtime cannot be verified.
type Authority interface {
	Resolve(context.Context, journal.Target, string) (Assignment, error)
	// WithVerifiedApplied runs commit only while the verified assignment remains
	// current. Authority transitions must serialize against the callback.
	WithVerifiedApplied(context.Context, AppliedReceipt, func() error) error
}

type Service struct {
	db        *sql.DB
	authority Authority
}

func New(db *sql.DB, authority Authority) (*Service, error) {
	if db == nil || authority == nil {
		return nil, errors.New("delivery requires a journal database and authority")
	}
	return &Service{db: db, authority: authority}, nil
}

// Next returns the pending command without clearing it. authenticatedNodeID
// comes from the transport's verified identity, never from a request body.
func (s *Service) Next(ctx context.Context, authenticatedNodeID string, target journal.Target) (Command, error) {
	if authenticatedNodeID == "" || authenticatedNodeID != target.NodeID {
		return Command{}, ErrUnauthorized
	}
	cmd, err := journal.Pending(ctx, s.db, target)
	if err != nil {
		return Command{}, err
	}
	assignment, err := s.authority.Resolve(ctx, target, cmd.ID)
	if err != nil {
		return Command{}, err
	}
	if !assignment.valid() {
		return Command{}, ErrUnauthorized
	}
	return Command{Command: cmd, Target: target, Assignment: assignment, PayloadHash: sha256.Sum256(cmd.Payload)}, nil
}

func (a Assignment) valid() bool {
	return a.Epoch > 0 && a.ExecutorID != "" && a.Incarnation != ""
}

// Confirm accepts only applied receipts. A transport delivery receipt or a
// rejected command cannot advance the journal revision.
func (s *Service) Confirm(ctx context.Context, authenticatedNodeID string, receipt AppliedReceipt) error {
	if authenticatedNodeID == "" || authenticatedNodeID != receipt.Target.NodeID {
		return ErrUnauthorized
	}
	if receipt.OperationID == "" || receipt.Revision <= 0 || !receipt.Assignment.valid() ||
		receipt.StateHash == [32]byte{} || receipt.RestartManifestHash == [32]byte{} {
		return ErrReceipt
	}
	assignment, err := s.authority.Resolve(ctx, receipt.Target, receipt.OperationID)
	if err != nil {
		return err
	}
	if assignment != receipt.Assignment {
		return ErrReceipt
	}
	return s.authority.WithVerifiedApplied(ctx, receipt, func() error {
		return journal.ConfirmApplied(ctx, s.db, receipt.Target, receipt.OperationID, receipt.Revision, receipt.PayloadHash)
	})
}
