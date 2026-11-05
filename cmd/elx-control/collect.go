package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/google/uuid"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/accounting"
)

// collect-usage is a privileged local-supervisor operation. The --node
// argument selects a pre-provisioned assignment; it is NOT a node identity
// assertion from a public request. No API listener exposes this command.
func collectUsage(ctx context.Context, db *sql.DB, args []string) error {
	a, err := parseCollection(args)
	if err != nil {
		return err
	}
	core, err := openCore()
	if err != nil {
		return err
	}
	defer core.Close()

	receipt, err := accounting.Collect(ctx, db, a.NodeID, a, core)
	if err != nil {
		return fmt.Errorf("collect signed usage: %w", err)
	}
	return json.NewEncoder(os.Stdout).Encode(receipt)
}

func parseCollection(args []string) (accounting.Assignment, error) {
	var a accounting.Assignment
	fs := flag.NewFlagSet("collect-usage", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var node, executor, incarnation, stream, period string
	fs.StringVar(&node, "node", "", "trusted node UUID")
	fs.StringVar(&executor, "executor", "", "assigned executor UUID")
	fs.StringVar(&incarnation, "incarnation", "", "pinned ElXray boot UUID")
	fs.StringVar(&stream, "accounting", "", "accounting stream UUID")
	fs.StringVar(&period, "period", "", "FUP period UUID")
	fs.Int64Var(&a.Generation, "generation", 0, "accounting generation")
	if fs.Parse(args) != nil || fs.NArg() != 0 || a.Generation <= 0 {
		return a, errors.New("collect-usage requires valid pre-provisioned node, executor, incarnation, accounting, generation and period")
	}
	ids := []*uuid.UUID{&a.NodeID, &a.ExecutorID, &a.Incarnation, &a.AccountingID, &a.PeriodID}
	values := []string{node, executor, incarnation, stream, period}
	for i, raw := range values {
		parsed, err := uuid.Parse(raw)
		if err != nil || parsed == uuid.Nil || parsed.String() != raw {
			return accounting.Assignment{}, errors.New("collect-usage requires canonical nonzero UUIDs")
		}
		*ids[i] = parsed
	}
	return a, nil
}
