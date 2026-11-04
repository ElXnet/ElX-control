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

// collect-current is a trusted local supervisor command. Unlike collect-usage,
// it resolves a scheduled period atomically with the signed readback and cannot
// accidentally credit the previous period after a calendar rollover.
func collectCurrent(ctx context.Context, db *sql.DB, args []string) error {
	a, schedule, err := parseCurrentCollection(args)
	if err != nil {
		return err
	}
	core, err := openCore()
	if err != nil {
		return err
	}
	defer core.Close()
	receipt, err := accounting.CollectCurrent(ctx, db, a.NodeID, schedule, a, core)
	if err != nil {
		return fmt.Errorf("collect current signed usage: %w", err)
	}
	return json.NewEncoder(os.Stdout).Encode(receipt)
}

func parseCurrentCollection(args []string) (accounting.Assignment, uuid.UUID, error) {
	var a accounting.Assignment
	var schedule uuid.UUID
	fs := flag.NewFlagSet("collect-current", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var node, executor, incarnation, stream, scheduleText string
	fs.StringVar(&node, "node", "", "trusted node UUID")
	fs.StringVar(&executor, "executor", "", "assigned executor UUID")
	fs.StringVar(&incarnation, "incarnation", "", "pinned core boot UUID")
	fs.StringVar(&stream, "accounting", "", "accounting stream UUID")
	fs.StringVar(&scheduleText, "schedule", "", "current FUP schedule UUID")
	fs.Int64Var(&a.Generation, "generation", 0, "accounting generation")
	if fs.Parse(args) != nil || fs.NArg() != 0 || a.Generation <= 0 {
		return a, schedule, errors.New("collect-current requires a trusted assignment and schedule")
	}
	ids := []*uuid.UUID{&a.NodeID, &a.ExecutorID, &a.Incarnation, &a.AccountingID, &schedule}
	for i, raw := range []string{node, executor, incarnation, stream, scheduleText} {
		id, err := uuid.Parse(raw)
		if err != nil || id == uuid.Nil || id.String() != raw {
			return accounting.Assignment{}, uuid.Nil, errors.New("collect-current requires canonical nonzero UUIDs")
		}
		*ids[i] = id
	}
	return a, schedule, nil
}
