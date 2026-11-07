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
	"time"

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


// armFUP is test-only: the already-provisioned, signed FUP stream must be
// fully primed, then the threshold is set 64KiB above current accepted usage.
// Only subsequent CORE-SIGNED payloads can create the actual threshold event.
func armFUP(ctx context.Context, db *sql.DB, entitlement string) error {
	if !canonical(entitlement) { return errors.New("invalid entitlement") }
	var schedule string
	var period string
	err := db.QueryRowContext(ctx, `SELECT s.id::text,p.id::text
		FROM elx_period_schedules s JOIN elx_usage_periods p
		  ON p.id=s.current_period_id
		WHERE s.entitlement_id=$1 AND p.entitlement_id=$1
		  AND p.ends_at>clock_timestamp() AND p.starts_at<=clock_timestamp()`,
		entitlement).Scan(&schedule,&period)
	if err != nil { return fmt.Errorf("FUP test schedule unavailable: %w",err) }
	store:=management.SQLStore{DB:db}
	activated,err:=store.ActivateSchedule(ctx,entitlement,schedule)
	if err!=nil{return fmt.Errorf("signed FUP coverage activation: %w",err)}
	if !activated.Enabled||!activated.Coverage.Ready||activated.Coverage.FreshGrants!=2{
		return errors.New("signed FUP coverage is not ready for both cores")
	}
	var threshold int64
	err=db.QueryRowContext(ctx,`UPDATE elx_usage_periods
		SET threshold_bytes=up_bytes+down_bytes+65536,
		    reduced_up=20000,reduced_down=20000
		WHERE id=$1 AND entitlement_id=$2
		AND up_bytes+down_bytes<100000000
		AND NOT EXISTS(SELECT 1 FROM elx_fup_events WHERE period_id=$1)
		RETURNING threshold_bytes`,period,entitlement).Scan(&threshold)
	if err!=nil{return fmt.Errorf("arm disposable signed FUP threshold: %w",err)}
	fmt.Printf("PASS: signed FUP armed at %d bytes total, 20k/20k caps\n",threshold)
	return nil
}

type fupState struct {
	Event bool `json:"event"`
	CommittedUp int64 `json:"committedUp"`
	CommittedDown int64 `json:"committedDown"`
	Pending int64 `json:"pending"`
	LeaderEpoch int64 `json:"leaderEpoch"`
	LeaderHolder string `json:"leaderHolder"`
}

func readFUPState(ctx context.Context,db *sql.DB,entitlement string) error {
	if !canonical(entitlement) {return errors.New("invalid entitlement")}
	var s fupState
	err:=db.QueryRowContext(ctx,`SELECT
	  EXISTS(SELECT 1 FROM elx_fup_events f JOIN elx_usage_periods p ON p.id=f.period_id
	    WHERE p.entitlement_id=$1 AND p.ends_at>clock_timestamp()),
	  COALESCE((SELECT sum(committed_up) FROM elx_rate_grants WHERE entitlement_id=$1),0),
	  COALESCE((SELECT sum(committed_down) FROM elx_rate_grants WHERE entitlement_id=$1),0),
	  (SELECT count(*) FROM elx_rate_moves m JOIN elx_rate_grants g USING(node_id,resource_id)
	    WHERE g.entitlement_id=$1 AND NOT m.finalized),
	  COALESCE((SELECT epoch FROM elx_rate_scheduler_leaders WHERE entitlement_id=$1),0),
	  COALESCE((SELECT holder_id::text FROM elx_rate_scheduler_leaders WHERE entitlement_id=$1),'')`,
		entitlement).Scan(&s.Event,&s.CommittedUp,&s.CommittedDown,
			&s.Pending,&s.LeaderEpoch,&s.LeaderHolder)
	if err!=nil{return err}
	return json.NewEncoder(os.Stdout).Encode(s)
}

func main() {
	if len(os.Args) < 3 || (os.Args[1] != "seed" && os.Args[1] != "inspect" && os.Args[1] != "arm-fup" && os.Args[1] != "fup-state") {
		fmt.Fprintln(os.Stderr, "usage: rate-scheduler-fixture seed <8 args> | inspect|arm-fup|fup-state <entitlement>")
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
	case "arm-fup":
        if len(os.Args)!=3 {err=errors.New("arm-fup requires entitlement")} else {err=armFUP(ctx,db,os.Args[2])}
    case "fup-state":
        if len(os.Args)!=3 {err=errors.New("fup-state requires entitlement")} else {err=readFUPState(ctx,db,os.Args[2])}
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
