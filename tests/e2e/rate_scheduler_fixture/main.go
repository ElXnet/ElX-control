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
	"time"

	"github.com/ElXnet/ElX-control/internal/elxcontrol/journal"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/management"
	"github.com/jackc/pgx/v5"
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
	if len(args) != 10 {
		return errors.New("seed: entitlement resource node0 incarnation0 key0 executor0 node1 incarnation1 key1 executor1")
	}
	for _, i := range []int{0, 1, 2, 3, 5, 6, 7, 9} {
		if !canonical(args[i]) {
			return fmt.Errorf("invalid fixture UUID at argument %d", i)
		}
	}
	signerKeys := make([][]byte, 2)
	for i, position := range []int{4, 8} {
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
	for i, position := range []int{2, 6} {
		provision := management.UsageProvision{
			ScheduleID: schedule.ScheduleID, NodeID: args[position],
			ResourceID: args[1], Incarnation: args[position+1],
			ExecutorID: args[position+3], AccountingID: uuid.NewString(),
			Generation: 1, SubscriptionID: "lab",
			ExpectedEpoch: 1, ExpectedPublicKey: signerKeys[i],
		}
		if _, err := store.ProvisionUsageStream(ctx, args[0], provision); err != nil {
			return fmt.Errorf("provision signed usage source %d: %w", i, err)
		}
	}
	return nil
}

// provisionWitness binds an existing disposable PostgreSQL core snapshot to
// an independently provisioned ElXray journal StoreID. It never trusts a
// node-supplied receipt as evidence of that initial authoritative baseline.
func provisionWitness(ctx context.Context, db *sql.DB, args []string) error {
	if len(args) != 4 {
		return errors.New("witness: node resource executor core-store UUID")
	}
	for _, id := range args {
		if !canonical(id) {
			return errors.New("witness requires four canonical UUIDs")
		}
	}
	return journal.ProvisionCoreStoreWitness(ctx, db, journal.CoreStoreWitness{
		NodeID: args[0], ResourceID: args[1], ExecutorID: args[2],
		StoreID: args[3], AuthorityGeneration: 1, CoreRevision: 1,
	})
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

type fupTargetState struct {
	Node string `json:"node"`
	CommittedUp int64 `json:"committedUp"`
	CommittedDown int64 `json:"committedDown"`
	Revision int64 `json:"revision"`
	DesiredUp int64 `json:"desiredUp"`
	DesiredDown int64 `json:"desiredDown"`
	Applied bool `json:"applied"`
}
type fupState struct {
	Targets []fupTargetState `json:"targets"`
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
	rows, err := db.QueryContext(ctx, `SELECT g.node_id::text, g.committed_up,
		g.committed_down, t.revision, COALESCE(m.desired_up,-1),
		COALESCE(m.desired_down,-1), COALESCE(o.applied_at IS NOT NULL,false)
		FROM elx_rate_grants g
		JOIN elx_operation_targets t ON t.node_id=g.node_id AND t.resource_id=g.resource_id
		LEFT JOIN elx_rate_moves m ON m.node_id=g.node_id
			AND m.resource_id=g.resource_id AND NOT m.finalized
		LEFT JOIN elx_operations o ON o.node_id=m.node_id
			AND o.resource_id=m.resource_id AND o.operation_id=m.operation_id
		WHERE g.entitlement_id=$1 ORDER BY g.node_id,g.resource_id`, entitlement)
	if err != nil {return err}
	defer rows.Close()
	for rows.Next(){
		var item fupTargetState
		if err := rows.Scan(&item.Node,&item.CommittedUp,&item.CommittedDown,
			&item.Revision,&item.DesiredUp,&item.DesiredDown,&item.Applied); err != nil {return err}
		s.Targets = append(s.Targets,item)
	}
	if err=rows.Err(); err!=nil{return err}
	return json.NewEncoder(os.Stdout).Encode(s)
}


type technicalSnapshot struct {
	ProfileState string `json:"profileState"`
	Operations map[string]string `json:"operations"`
	StoreID string `json:"storeId"`
	CoreBoot string `json:"coreBoot"`
	CoreRevision int64 `json:"coreRevision"`
	CommittedUp int64 `json:"committedUp"`
	CommittedDown int64 `json:"committedDown"`
	ActiveSlots int64 `json:"activeSlots"`
}

// Independent read-only Control snapshot, only for guarded disposable elx_test.
func technicalState(ctx context.Context, db *sql.DB, args []string) error {
	if len(args)!=2 || !canonical(args[0]) || !canonical(args[1]) {
		return errors.New("technical-state requires canonical profile and node UUIDs")
	}
	var s technicalSnapshot
	s.Operations=make(map[string]string)
	err:=db.QueryRowContext(ctx,`SELECT p.state,w.store_id::text,
	    COALESCE(w.core_incarnation::text,''),w.core_revision,
	    g.committed_up,g.committed_down,e.active_slots
	    FROM elx_technical_profiles p
	    JOIN elx_core_store_witnesses w ON w.node_id=p.node_id
	    AND w.resource_id=p.resource_id
	    JOIN elx_rate_grants g ON g.node_id=p.node_id AND g.resource_id=p.resource_id
	    AND g.entitlement_id=p.entitlement_id
	    JOIN elx_entitlements e ON e.id=p.entitlement_id
	    WHERE p.profile_id=$1 AND p.node_id=$2`,args[0],args[1]).Scan(
	    &s.ProfileState,&s.StoreID,&s.CoreBoot,&s.CoreRevision,
	    &s.CommittedUp,&s.CommittedDown,&s.ActiveSlots)
	if err!=nil{return err}
	rows,err:=db.QueryContext(ctx,`SELECT action,state
	    FROM elx_technical_profile_operations WHERE profile_id=$1 ORDER BY action`,args[0])
	if err!=nil{return err}
	defer rows.Close()
	for rows.Next(){
		var action,state string
		if err=rows.Scan(&action,&state);err!=nil{return err}
		if _,duplicate:=s.Operations[action];duplicate{
			return errors.New("duplicate technical operation action")
		}
		s.Operations[action]=state
	}
	if err=rows.Err();err!=nil{return err}
	return json.NewEncoder(os.Stdout).Encode(s)
}

func main() {
	if len(os.Args) < 3 || (os.Args[1] != "seed" && os.Args[1] != "witness" && os.Args[1] != "inspect" && os.Args[1] != "arm-fup" && os.Args[1] != "fup-state" && os.Args[1] != "technical-state") {
		fmt.Fprintln(os.Stderr, "usage: rate-scheduler-fixture seed <10 args> | witness <node resource executor store> | inspect|arm-fup|fup-state <entitlement>")
		os.Exit(2)
	}
	dsn := os.Getenv("ELX_CONTROL_POSTGRES_DSN")
	// Fail closed on an unknown DSN. Acceptance tests use a fresh Docker
	// database named elx_test, never live subscriptions or payments.
	cfg, parseErr := pgx.ParseConfig(dsn)
	if parseErr != nil || cfg.Database != "elx_test" ||
		(cfg.Host != "127.0.0.1" && cfg.Host != "::1") || cfg.Port == 0 {
		fmt.Fprintln(os.Stderr, "refusing non-loopback or non-disposable PostgreSQL database")
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
	case "technical-state":
        err = technicalState(ctx, db, os.Args[2:])
	case "witness":
		err = provisionWitness(ctx, db, os.Args[2:])
		if err == nil {
			fmt.Println("PASS: separately pinned disposable core store HWM")
		}
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
