package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/base64"
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
	technical := os.Getenv("ELX_AGENT_TECHNICAL_PREPARE")
	if technical != "" && technical != "1" {
		return errors.New("unsupported technical provisioning agent flag")
	}
	installEnabled := os.Getenv("ELX_AGENT_TECHNICAL_INSTALL")
	if installEnabled != "" && installEnabled != "1" {
		return errors.New("unsupported signed technical INSTALL agent flag")
	}
	if installEnabled == "1" && technical != "1" {
		return errors.New("signed INSTALL requires independently pinned PREPARE mode")
	}
	var technicalPublicKey ed25519.PublicKey
	if technical == "1" {
		if os.Getenv("ELX_AGENT_MANAGED") != "1" ||
			os.Getenv("ELX_AGENT_LEASE_REQUIRED") != "1" {
			return errors.New("technical provisioning requires managed signed lease mode")
		}
		decoded, err := base64.StdEncoding.DecodeString(os.Getenv("ELXRAY_CONTROL_LEASE_PUBLIC_KEY"))
		if err != nil || len(decoded) != ed25519.PublicKeySize {
			return errors.New("technical provisioning requires pinned Control public key")
		}
		technicalPublicKey = ed25519.PublicKey(decoded)
	}
	if os.Getenv("ELX_AGENT_MANAGED") == "1" {
		if os.Getenv("ELX_AGENT_LEASE_REQUIRED") != "1" ||
			os.Getenv("ELXRAY_POLICY_SOCKET") == "" ||
			os.Getenv("ELXRAY_POLICY_LOOPBACK") != "" {
			return errors.New("managed agent requires signed leases and authenticated Unix Commander only")
		}
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
		// Stage 4 prepares technical identities only. The same signed job
		// remains in Control INTENT; no owner reservation or payload grant
		// is inferred from this non-authorizing core readback.
		if technical == "1" {
			bindings, loadErr := loadBindings()
			if loadErr != nil {
				return fmt.Errorf("trusted technical profile manifest unavailable: %w", loadErr)
			}
			prepareCtx, prepareCancel := context.WithTimeout(ctx, 10*time.Second)
			prepareErr := policytransport.ApplyTechnicalPreparation(
				prepareCtx, conn, core, bindings, technicalPublicKey)
			prepareCancel()
			if ctx.Err() != nil {
				return nil
			}
			if prepareErr != nil {
				switch status.Code(prepareErr) {
				case codes.NotFound:
					// No approved technical reservation to prepare.
				case codes.Unavailable, codes.DeadlineExceeded, codes.FailedPrecondition:
					// No speculative ACK or traffic allowance. Retry after
					// the lease and protected core journal become ready.
					fmt.Fprintln(os.Stderr, "ElX technical preparation not yet confirmed; will retry:", prepareErr)
				default:
					return fmt.Errorf("technical profile preparation failed closed: %w", prepareErr)
				}
			}
		}
		// Signed v2 INSTALL is a separate opt-in from the non-admitting
		// v1 PREPARE. APPLIED requires verified core-signed evidence on
		// Control's PostgreSQL primary; a lost reply is never assumed safe.
		if installEnabled == "1" {
			bindings, err := loadBindings()
			if err != nil {
				return fmt.Errorf("technical INSTALL manifest unavailable: %w", err)
			}
			installCtx, done := context.WithTimeout(ctx, 15*time.Second)
			err = policytransport.ApplyTechnicalInstall(
				installCtx, conn, core, bindings, technicalPublicKey)
			done()
			if ctx.Err() != nil {
				return nil
			}
			if err != nil {
				switch status.Code(err) {
				case codes.NotFound:
					// No authoritative INSTALL intent on this executor.
				case codes.Unavailable, codes.DeadlineExceeded, codes.FailedPrecondition:
					// Never advance without a pinned Control confirmation.
					fmt.Fprintln(os.Stderr, "ElX technical INSTALL requires reconciliation:", err)
				default:
					return fmt.Errorf("signed technical INSTALL failed closed: %w", err)
				}
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
		// A committed reduction is released ONLY after ElXray proves that
		// all traffic authorized under the prior higher limit has drained.
		barrierCtx, barrierCancel := context.WithTimeout(ctx, 45*time.Second)
		barrierErr := policytransport.ApplyRateBarrier(barrierCtx, conn, core)
		barrierCancel()
		if ctx.Err()!=nil {return nil}
		if barrierErr!=nil {
			switch status.Code(barrierErr) {
			case codes.NotFound:
				// No applied rate move awaiting a separate core barrier.
			case codes.Unavailable,codes.DeadlineExceeded,codes.FailedPrecondition:
				// Keep old speed reservations occupied until a valid proof.
				fmt.Fprintln(os.Stderr,"ElX rate reduction still conservatively reserved:",barrierErr)
			default:
				return fmt.Errorf("rate barrier failed closed: %w",barrierErr)
			}
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}
