package main

import (
	"context"
	"database/sql"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/ElXnet/ElX-control/internal/elxcontrol/journal"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/scheduler"
	"github.com/google/uuid"
)

// serveScheduler is intentionally opt-in. This isolates dynamic bandwidth
// allocation from ordinary Control upgrades until the node/lease network
// acceptance matrix and operator rollout policy have been approved.
func serveScheduler(ctx context.Context, db *sql.DB, args []string) error {
	if os.Getenv("ELX_RATE_SCHEDULER_ENABLED")!="1" {
		return errors.New("dynamic scheduling is disabled: set ELX_RATE_SCHEDULER_ENABLED=1 explicitly")
	}
	fs:=flag.NewFlagSet("serve-scheduler",flag.ContinueOnError)
	interval:=fs.Duration("interval",5*time.Second,"authenticated demand reconciliation cadence")
	ttl:=fs.Duration("leader-ttl",15*time.Second,"PostgreSQL leader fence TTL")
	if err:=fs.Parse(args);err!=nil{return err}
	if fs.NArg()!=0 || *interval<time.Second || *interval>time.Minute ||
		*ttl<5*time.Second || *ttl>30*time.Second || *interval>=*ttl {
		return errors.New("invalid scheduler interval/lease TTL")
	}
	// A fresh, random incarnation per process prevents two physical Control
	// instances from accidentally sharing the same leader identity.
	holder,err:=uuid.NewRandom()
	if err!=nil{return err}
	w:=scheduler.Worker{
		DB:db,Holder:holder,Interval:*interval,LeaderTTL:*ttl,
		OnDecision:func(entitlement string,r journal.DemandRebalanceResult){
			if r.OperationID!=""{
				fmt.Fprintf(os.Stderr,"ElX rate operation reserved: entitlement=%s target=%s/%s operation=%s phase=%s\n",
					entitlement,r.Target.NodeID,r.Target.ResourceID,r.OperationID,r.Phase)
			}
		},
	}
	return w.Run(ctx)
}
