package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"os"

	"github.com/ElXnet/ElX-control/internal/elxcontrol/journal"
)

func quarantineTechnicalNode(ctx context.Context, db *sql.DB, args []string) error {
	fs := flag.NewFlagSet("quarantine-technical-node", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	node := fs.String("node", "", "exact node UUID")
	resource := fs.String("resource", "", "pinned resource UUID")
	profile := fs.String("profile", "", "original technical VLESS UUID")
	operation := fs.String("operation", "", "unresolved original operation UUID")
	store := fs.String("store", "", "independently pinned Control store UUID")
	phase := fs.String("phase", "", "offline inspected INSTALLING or RETIRING")
	evidence := fs.String("evidence-sha256", "", "SHA-256 of archived offline journal inspection evidence")
	operator := fs.String("operator", "", "audit reference of approving operator")
	confirm := fs.String("confirm-node", "", "repeat the exact isolated node UUID")
	fenced := fs.Bool("physically-fenced", false, "acknowledge that this node is isolated outside Control")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || !*fenced {
		return errors.New("explicit physical isolation and --physically-fenced are required")
	}
	request := journal.TechnicalNodeQuarantine{
		NodeID: *node, ResourceID: *resource, ProfileID: *profile,
		OperationID: *operation, StoreID: *store, Phase: *phase,
		EvidenceSHA256: *evidence, OperatorRef: *operator, ConfirmedNode: *confirm,
	}
	if err := journal.QuarantineTechnicalNode(ctx, db, request); err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"nodeId": *node, "operationId": *operation,
		"quarantined": true, "authorizesPayload": false,
		"confirmsApplied": false, "releasesPaidCapacity": false,
	})
}
