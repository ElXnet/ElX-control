package main

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
)

func TestOperatorQuarantineCLIRequiresExplicitPhysicalFence(t *testing.T) {
	node := uuid.NewString()
	args := []string{
		"-node", node,
		"-resource", uuid.NewString(),
		"-profile", uuid.NewString(),
		"-operation", uuid.NewString(),
		"-store", uuid.NewString(),
		"-phase", "INSTALLING",
		"-evidence-sha256", "1111111111111111111111111111111111111111111111111111111111111111",
		"-operator", "operator-test",
		"-confirm-node", node,
	}
	// A usable database handle alone does not authorize a quarantine.
	if err := quarantineTechnicalNode(context.Background(), &sql.DB{}, args); err == nil {
		t.Fatal("operator command accepted an incident without explicit physical isolation")
	}
	if err := quarantineTechnicalNode(context.Background(), &sql.DB{},
		append(append([]string(nil), args...), "-physically-fenced", "true", "unexpected")); err == nil {
		t.Fatal("quarantine accepted unexpected unreviewed arguments")
	}
}
