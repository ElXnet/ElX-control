package journal

import (
	"context"
	"database/sql"
	"errors"
	"math"
	"testing"
)

func TestInvalidCommandsDoNotAccessDatabase(t *testing.T) {
	for _, cmd := range []Command{
		{},
		{ExpectedRevision: -1, Payload: []byte{1}},
		{ExpectedRevision: math.MaxInt64, Payload: []byte{1}},
		{Payload: make([]byte, 256*1024+1)},
	} {
		if _, err := Enqueue(context.Background(), nil, Target{}, cmd); !errors.Is(err, ErrInvalid) {
			t.Fatalf("expected invalid command, got %v", err)
		}
	}
}

func TestInvalidReceiptDoesNotAccessDatabase(t *testing.T) {
	if err := ConfirmApplied(context.Background(), nil, Target{}, "", 0, [32]byte{}); !errors.Is(err, ErrReceipt) {
		t.Fatalf("expected invalid receipt, got %v", err)
	}
}

func checkError(t *testing.T, got, want error) {
	t.Helper()
	if !errors.Is(got, want) {
		t.Fatalf("error = %v, want %v", got, want)
	}
}

func checkPending(t *testing.T, db *sql.DB, target Target, id string) {
	t.Helper()
	cmd, err := Pending(context.Background(), db, target)
	checkError(t, err, nil)
	if cmd.ID != id {
		t.Fatalf("pending command = %q, want %q", cmd.ID, id)
	}
}
