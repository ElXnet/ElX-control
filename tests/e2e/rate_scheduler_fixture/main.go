// Command rate-scheduler-fixture provisions and observes a disposable
// signed-telemetry scheduler acceptance lab. It cannot accept a production DSN.
// This is NOT part of the elx-control operator binary.
package main

import (
	"context"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/ElXnet/ElX-control/internal/elxcontrol/journal"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/management"
	"github.com/google/uuid"
	_ "github.com/jackc/pgx/v5/stdlib"
)

func canonical(raw string) bool {
	id, err := uuid.Parse(raw)
	return err == nil && id != uuid.Nil && id.String() == raw
}

func seed(ctx context.Context, db *sql.DB, args []string) error {
	// Existing seed_lease.go has already provisioned the exact entitlement,
	// pinned cores, policy revisions and committed rate grants.
	if len(args) != 8 {
		return errors.New("seed: entitlement resource node0 incarnation0 key0 node1 incarnation1 key1")
	}
	for _, i := range []int{0, 1, 2, 3, 5, 6} {
		if !canonical(args[i]) {
			return fmt.Errorf("invalid fixture UUID at argument %d", i)
		}
	}
	signerKeys := make([][]byte, 2)
	for i, position := range []int{4, 7} {
		key, err := base64.StdEncoding.DecodeString(args[position])
		if err != nil || len(key) != 32 {
			return errors.New("invalid pinned ElXray public key")
		}
		signerKeys[i] = key
	}
	store := management.SQLStore{DB: db}
	schedule := management.ScheduleSpec{
		ScheduleID: uuid.NewString(), Cadence: "day", Timezone: "UTC",
		Direction: "total", ThresholdBytes: 1000000000,
		ReducedUp: 50000, ReducedDown: 50000,
	}
	if _, err := store.CreateSchedule(ctx, args[0], schedule); err != nil {
		return fmt.Errorf("create acceptance accounting schedule: %w", err)
	}
	for i, position := range []int{2, 5} {
		provision := management.UsageProvision{
			ScheduleID: schedule.ScheduleID, NodeID: args[position],
			ResourceID: args[1], Incarnation: args[position+1],
			ExecutorID: uuid.NewString(), AccountingID: uuid.NewString(),
			Generation: 1, SubscriptionID: "lab",
			ExpectedEpoch: 1, ExpectedPublicKey: signerKeys[i],
		}
		if _, err := store.ProvisionUsageStream(ctx, args[0], provision); err != nil {
			return fmt.Errorf("provision signed usage source %d: %w", i, err)
		}
	}
	return nil
}

func inspect(ctx context.Context, db *sql.DB, entitlement string) error {
	if !canonical(entitlement) {
		return errors.New("invalid entitlement UUID")
	}
	// PreviewDemand never trusts an HTTP/node-provided demand number.
	// Two verified signed ElXray pressure samples and a core-accepted
	// Control lease are required for each returned target.
	verified, err := journal.PreviewDemand(ctx, db, entitlement)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(verified)
}

func main() {
	if len(os.Args) < 3 || (os.Args[1] != "seed" && os.Args[1] != "inspect") {
		fmt.Fprintln(os.Stderr, "usage: rate-scheduler-fixture seed <8 args> | inspect <entitlement>")
		os.Exit(2)
	}
	dsn := os.Getenv("ELX_CONTROL_POSTGRES_DSN")
	// Fail closed on an unknown DSN. Acceptance tests use a fresh Docker
	// database named elx_test, never live subscriptions or payments.
	if dsn == "" || !strings.Contains(dsn, "elx_test") {
		fmt.Fprintln(os.Stderr, "refusing to touch a database without the disposable elx_test marker")
		os.Exit(2)
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer db.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	switch os.Args[1] {
	case "seed":
		err = seed(ctx, db, os.Args[2:])
		if err == nil {
			fmt.Println("PASS: signed telemetry streams provisioned for both cores")
		}
	case "inspect":
		if len(os.Args) != 3 {
			err = errors.New("inspect requires exactly one entitlement")
		} else {
			err = inspect(ctx, db, os.Args[2])
		}
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
