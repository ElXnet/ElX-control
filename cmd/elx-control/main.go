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
		return errors.New("usage: elx-control inspect-technical-recovery|enqueue-technical-profile|enqueue-technical-install|enqueue-technical-retire|migrate|bootstrap-store-witness|serve-scheduler|issue-invite|serve-management|serve-payment-ingress|serve-policy|serve-agent|serve-usage|drain-profile|enqueue-drain|enqueue-policy|apply-policy|policy-public-key|read-usage|collect-usage|collect-current|provision-usage|auto-provision-usage|usage-coverage|activate-fup|queue-rate-move|begin-core-rotation|complete-core-rotation|reconcile-fup|serve-fup|advance-periods")
	}
	switch args[0] {
	case "policy-public-key":
		return printPolicyKey(args[1:])
	case "read-usage":
		return readUsage(ctx, args[1:])
	case "serve-agent":
		return serveAgent(ctx, args[1:])
	case "serve-usage":
		return serveUsage(ctx, args[1:])
	case "drain-profile":
		return drainProfile(ctx, args[1:])
	case "apply-policy":
		if len(args) != 1 {
			return errors.New("usage: elx-control apply-policy")
		}
		return applyPolicy(ctx)
	case "inspect-technical-recovery", "enqueue-technical-profile", "enqueue-technical-install", "enqueue-technical-retire", "bootstrap-store-witness", "migrate", "serve-scheduler", "issue-invite", "serve-management", "serve-payment-ingress", "serve-policy", "enqueue-policy", "enqueue-drain", "collect-usage", "collect-current", "provision-usage", "auto-provision-usage", "usage-coverage", "activate-fup", "queue-rate-move", "begin-core-rotation", "complete-core-rotation", "reconcile-fup", "serve-fup", "advance-periods":
	default:
		return errors.New("unknown elx-control command")
	}
	if args[0] != "inspect-technical-recovery" && args[0] != "enqueue-technical-profile" && args[0] != "enqueue-technical-install" && args[0] != "enqueue-technical-retire" && args[0] != "bootstrap-store-witness" && args[0] != "serve-scheduler" && args[0] != "issue-invite" && args[0] != "enqueue-policy" && args[0] != "enqueue-drain" && args[0] != "collect-usage" && args[0] != "collect-current" && args[0] != "provision-usage" && args[0] != "auto-provision-usage" && args[0] != "usage-coverage" && args[0] != "activate-fup" && args[0] != "queue-rate-move" && args[0] != "begin-core-rotation" && args[0] != "complete-core-rotation" && args[0] != "reconcile-fup" && args[0] != "serve-fup" && args[0] != "advance-periods" && len(args) != 1 {
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
	case "inspect-technical-recovery":
		return inspectTechnicalRecovery(ctx, db, args[1:])
	case "enqueue-technical-profile":
		return enqueueTechnicalProfile(ctx, db, args[1:])
	case "enqueue-technical-install":
		return enqueueTechnicalInstall(ctx, db, args[1:])
	case "enqueue-technical-retire":
		return enqueueTechnicalRetire(ctx, db, args[1:])
	case "bootstrap-store-witness":
		return bootstrapStoreWitness(ctx, db, args[1:])
	case "serve-scheduler":
		return serveScheduler(ctx, db, args[1:])
	case "serve-policy":
		return servePolicy(ctx, db)
	case "serve-management":
		return serveManagement(ctx, db)
	case "serve-payment-ingress":
		return servePaymentIngress(ctx,db)
	case "issue-invite":
		return issueInvite(ctx, db, args[1:])
	case "enqueue-policy":
		return enqueuePolicy(setup, db, args[1:])
	case "enqueue-drain":
		return enqueueDrain(ctx, db, args[1:])
	case "collect-usage":
		return collectUsage(ctx, db, args[1:])
	case "collect-current":
		return collectCurrent(ctx, db, args[1:])
	case "provision-usage":
		return provisionUsage(ctx, db, args[1:])
	case "auto-provision-usage":
		return autoProvisionUsage(ctx, db, args[1:])
	case "usage-coverage":
		return usageCoverage(ctx, db, args[1:])
	case "activate-fup":
		return activateFUP(ctx, db, args[1:])
	case "queue-rate-move":
		return queueRateMove(ctx,db,args[1:])
	case "begin-core-rotation":
		return beginCoreRotation(ctx,db,args[1:])
	case "complete-core-rotation":
		return completeCoreRotation(ctx,db,args[1:])
	case "reconcile-fup", "serve-fup":
		return runFUP(ctx, db, args[1:], args[0] == "serve-fup")
	case "advance-periods":
		return advancePeriods(ctx, db, args[1:])
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
