// Command elx-control manages the ElX Control database.
package main

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"os/signal"
	"syscall"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/journal"
)

func run(ctx context.Context, args []string, dsn string) error {
	if len(args) == 0 {
		return errors.New("usage: elx-control migrate|serve-policy|serve-agent|enqueue-policy|apply-policy|policy-public-key|read-usage|collect-usage|reconcile-fup|serve-fup")
	}
	switch args[0] {
	case "policy-public-key":
		return printPolicyKey(args[1:])
	case "read-usage":
		return readUsage(ctx, args[1:])
	case "serve-agent":
		return serveAgent(ctx, args[1:])
	case "apply-policy":
		if len(args) != 1 {
			return errors.New("usage: elx-control apply-policy")
		}
		return applyPolicy(ctx)
	case "migrate", "serve-policy", "enqueue-policy", "collect-usage", "reconcile-fup", "serve-fup":
	default:
		return errors.New("unknown elx-control command")
	}
	if args[0] != "enqueue-policy" && args[0] != "collect-usage" && args[0] != "reconcile-fup" && args[0] != "serve-fup" && len(args) != 1 {
		return errors.New("unexpected arguments")
	}
	if dsn == "" {
		return errors.New("ELX_CONTROL_POSTGRES_DSN is required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return errors.New("invalid Control database configuration")
	}
	defer db.Close()
	setup, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	if err := db.PingContext(setup); err != nil {
		return errors.New("cannot connect to Control database")
	}
	if err := journal.Migrate(setup, db); err != nil {
		return err
	}
	switch args[0] {
	case "serve-policy":
		return servePolicy(ctx, db)
	case "enqueue-policy":
		return enqueuePolicy(setup, db, args[1:])
	case "collect-usage":
		return collectUsage(ctx, db, args[1:])
	case "reconcile-fup", "serve-fup":
		return runFUP(ctx, db, args[1:], args[0] == "serve-fup")
	default:
		return nil
	}
}

func main() {
	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()
	if err := run(ctx, os.Args[1:], os.Getenv("ELX_CONTROL_POSTGRES_DSN")); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
