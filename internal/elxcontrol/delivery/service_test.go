package delivery

import (
	"context"
	"errors"
	"testing"

	"github.com/ElXnet/ElX-control/internal/elxcontrol/journal"
)

type testAuthority struct {
	assignment Assignment
	verifyErr  error
}

func (a testAuthority) Resolve(context.Context, journal.Target, string) (Assignment, error) {
	return a.assignment, nil
}

func (a testAuthority) WithVerifiedApplied(_ context.Context, _ AppliedReceipt, commit func() error) error {
	if a.verifyErr != nil {
		return a.verifyErr
	}
	return commit()
}

func TestRejectReceiptBeforeJournalWrite(t *testing.T) {
	ctx := context.Background()
	assignment := Assignment{Epoch: 2, ExecutorID: "executor", Incarnation: "core"}
	unavailable := errors.New("durable evidence unavailable")
	service := Service{authority: testAuthority{assignment: assignment, verifyErr: unavailable}}
	valid := AppliedReceipt{
		Target:      journal.Target{NodeID: "node", ResourceID: "resource"},
		OperationID: "operation", Revision: 1, Assignment: assignment,
		StateHash: [32]byte{1}, RestartManifestHash: [32]byte{2},
	}
	stale := valid
	stale.Assignment.Epoch--
	restarted := valid
	restarted.Assignment.Incarnation = "other core"
	missing := valid
	missing.RestartManifestHash = [32]byte{}
	for _, tc := range []struct {
		name, node string
		receipt    AppliedReceipt
		want       error
	}{
		{"wrong node", "other node", valid, ErrUnauthorized},
		{"old epoch", "node", stale, ErrReceipt},
		{"other incarnation", "node", restarted, ErrReceipt},
		{"missing restart evidence", "node", missing, ErrReceipt},
		{"verifier unavailable", "node", valid, unavailable},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := service.Confirm(ctx, tc.node, tc.receipt); !errors.Is(err, tc.want) {
				t.Fatalf("got %v, want %v", err, tc.want)
			}
		})
	}
}
