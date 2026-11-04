package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"time"

	"github.com/ElXnet/ElX-control/internal/elxcontrol/accounting"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/usagetransport"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
)

// usageBindings is trusted local provisioning, not an API request. Control
// still verifies each assignment against mTLS, its database and a core key.
func usageBindings() ([]accounting.RemoteBinding, error) {
	path := os.Getenv("ELX_USAGE_BINDINGS")
	if path == "" {
		return nil, errors.New("ELX_USAGE_BINDINGS file is required")
	}
	file, err := os.Open(path)
	if err != nil { return nil, err }
	defer file.Close()
	data, err := io.ReadAll(io.LimitReader(file, 1<<20+1))
	if err != nil || len(data) > 1<<20 { return nil, errors.New("usage binding file unavailable or too large") }
	var bindings []accounting.RemoteBinding
	if err := json.Unmarshal(data, &bindings); err != nil {
		var single accounting.RemoteBinding
		if json.Unmarshal(data, &single) != nil {
			return nil, errors.New("invalid usage binding JSON")
		}
		bindings = []accounting.RemoteBinding{single}
	}
	if len(bindings) == 0 || len(bindings) > 10000 {
		return nil, errors.New("usage binding count is outside safe limits")
	}
	seen := make(map[accounting.RemoteBinding]bool, len(bindings))
	for _, binding := range bindings {
		if !binding.Valid() || seen[binding] {
			return nil, errors.New("invalid or duplicate usage binding")
		}
		seen[binding] = true
	}
	return bindings, nil
}

// serveUsage runs on a VPN node, not the master PostgreSQL host. It carries
// only opaque core-signed evidence and cannot choose the billable subscription
// or the current FUP period. FailedPrecondition is retried after rollover.
func serveUsage(ctx context.Context, args []string) error {
	fs := flag.NewFlagSet("serve-usage", flag.ContinueOnError)
	interval := fs.Duration("interval", 5*time.Second, "signed usage poll interval (1s..1h)")
	once := fs.Bool("once", false, "collect each provisioned stream once and exit")
	if err := fs.Parse(args); err != nil { return err }
	if fs.NArg() != 0 || *interval < time.Second || *interval > time.Hour {
		return errors.New("usage poll interval must be 1s..1h")
	}
	// Optional legacy file for operators already using static bindings. The
	// normal path is authoritative discovery over mTLS on every poll.
	static := os.Getenv("ELX_USAGE_BINDINGS") != ""
	var bindings []accounting.RemoteBinding
	var err error
	if static {
		bindings, err = usageBindings()
		if err != nil { return err }
	}
	cfg, err := transportTLS()
	if err != nil { return err }
	cfg.MinVersion = tls.VersionTLS13
	endpoint := os.Getenv("ELX_POLICY_CONTROL")
	if endpoint == "" { return errors.New("ELX_POLICY_CONTROL is required") }
	conn, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(credentials.NewTLS(cfg)),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(1<<20)))
	if err != nil { return err }
	defer conn.Close()
	core, err := openCore()
	if err != nil { return err }
	defer core.Close()
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	for {
		if ctx.Err() != nil { return nil }
		if !static {
			callCtx,cancel:=context.WithTimeout(ctx,15*time.Second)
			discovered,discoverErr:=usagetransport.DiscoverBindings(callCtx,conn)
			cancel()
			if ctx.Err()!=nil{return nil}
			if discoverErr!=nil {
				switch status.Code(discoverErr) {
				case codes.Unavailable,codes.DeadlineExceeded,codes.FailedPrecondition:
					if *once {return discoverErr}
					fmt.Fprintln(os.Stderr,"ElX signed usage bindings unavailable; retrying:",status.Code(discoverErr))
				default:
					return fmt.Errorf("signed usage discovery stopped (fail closed): %w",discoverErr)
				}
			}else{
				bindings=discovered
			}
			// Never use a previous discovery snapshot when the master is
			// unavailable: a revoked assignment may have been removed.
			if discoverErr!=nil {bindings=nil}
		}
		if *once && len(bindings)==0{return errors.New("no Control-assigned signed usage streams")}
		for _, binding := range bindings {
			callCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
			receipt, err := usagetransport.PollOne(callCtx, conn, core, binding)
			cancel()
			if ctx.Err() != nil { return nil }
			if err != nil {
				switch status.Code(err) {
				case codes.Unavailable, codes.DeadlineExceeded, codes.FailedPrecondition:
					if *once { return err }
					fmt.Fprintln(os.Stderr, "ElX signed usage not accepted; retrying after next poll:", status.Code(err))
				default:
					return fmt.Errorf("signed usage collection stopped (fail closed): %w", err)
				}
			} else if *once {
				// Show the accepted high-watermark, not an assumed transfer.
				fmt.Printf("node=%s stream=%s sequence=%d duplicate=%v crossed=%v\n",
					binding.NodeID, binding.AccountingID,
					receipt.Sequence, receipt.Duplicate, receipt.Crossed)
			}
		}
		if *once { return nil }
		select {
		case <-ctx.Done(): return nil
		case <-ticker.C:
		}
	}
}
