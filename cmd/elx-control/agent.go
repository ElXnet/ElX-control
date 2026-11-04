package main

import (
	"context"
	"crypto/tls"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/ElXnet/ElX-control/internal/elxcontrol/policytransport"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/fencetransport"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

// serveAgent continuously checks Control for assigned policies and applies
// each revision to the local ElXray. It retries lost receipts with the same
// operation ID: Control keeps the command until a durable proof is confirmed.
func serveAgent(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("serve-agent", flag.ContinueOnError)
	interval := fs.Duration("interval", 2*time.Second, "poll interval (200ms..1h)")
	if err := fs.Parse(args); err != nil {
		return err
	}
	if fs.NArg() != 0 || *interval < 200*time.Millisecond || *interval > time.Hour {
		return errors.New("invalid agent polling interval")
	}
	cfg, err := transportTLS()
	if err != nil {
		return err
	}
	cfg.MinVersion = tls.VersionTLS13
	endpoint := os.Getenv("ELX_POLICY_CONTROL")
	if endpoint == "" {
		return errors.New("ELX_POLICY_CONTROL is required")
	}
	conn, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(credentials.NewTLS(cfg)),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(4096)))
	if err != nil {
		return err
	}
	defer conn.Close()
	core, err := openCore()
	if err != nil {
		return err
	}
	defer core.Close()
	// Lease keepalives must be independent of slow drain operations; a
	// blocked 30-second VLESS drain must not silently expire unrelated
	// subscriptions if the Control channel is otherwise healthy.
	if os.Getenv("ELX_AGENT_LEASE_REQUIRED")=="1" {
		bindings,err:=loadBindings()
		if err!=nil {return fmt.Errorf("lease bindings unavailable: %w",err)}
		for _,binding:=range bindings {
			binding:=binding
			go func(){
				ticker:=time.NewTicker(3*time.Second)
				defer ticker.Stop()
				for {
					if ctx.Err()!=nil{return}
					renewCtx,cancel:=context.WithTimeout(ctx,6*time.Second)
					err:=policytransport.ApplyLease(renewCtx,conn,core,binding)
					cancel()
					if ctx.Err()!=nil{return}
					if err!=nil {
						// Do not synthesize keepalives or clear the local
						// deadline. ElXray closes flows after 15 seconds.
						fmt.Fprintln(os.Stderr,"ElX Control lease not renewed; core will fail closed:",err)
					}
					select {
					case <-ctx.Done():return
					case <-ticker.C:
					}
				}
			}()
		}
	}
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	for {
		callCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		err := policytransport.ApplyNext(callCtx, conn, core)
		cancel()
		if ctx.Err() != nil {
			return nil
		}
		if err != nil {
			switch status.Code(err) {
			case codes.NotFound:
				// No pending command.
			case codes.Unavailable, codes.DeadlineExceeded:
				// Reconnect/retry on the next poll. Unknown outcome is safe:
				// Control does not dequeue without a signed applied receipt.
				fmt.Fprintln(os.Stderr, "ElX policy channel unavailable; will retry")
			default:
				// Malformed, unauthorized or mismatched policy evidence must
				// stop the worker instead of silently re-trying indefinitely.
				return fmt.Errorf("policy application failed closed: %w", err)
			}
		}
		// Drain tasks are authorized and persisted centrally; the node never
		// invents an OwnerID or frees a slot simply because traffic is idle.
		drainCtx, done := context.WithTimeout(ctx, 40*time.Second)
		drainErr := fencetransport.ApplyNext(drainCtx, conn, core)
		done()
		if ctx.Err() != nil {
			return nil
		}
		if drainErr != nil {
			switch status.Code(drainErr) {
			case codes.NotFound:
				// No Control-approved session termination for this node.
			case codes.Unavailable, codes.DeadlineExceeded:
				fmt.Fprintln(os.Stderr, "ElX session drain evidence not confirmed; retrying")
			default:
				// Wrong core boot, profile or key: keep the owner occupied and
				// require explicit operator reconciliation instead of guessing.
				return fmt.Errorf("session drain failed closed: %w", drainErr)
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
