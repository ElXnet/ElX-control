package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/google/uuid"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/corepolicy"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/journal"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/policytransport"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func transportTLS() (*tls.Config, error) {
	cert, err := tls.LoadX509KeyPair(os.Getenv("ELX_TLS_CERT"), os.Getenv("ELX_TLS_KEY"))
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(os.Getenv("ELX_TLS_CA"))
	if err != nil {
		return nil, err
	}
	ca := x509.NewCertPool()
	if !ca.AppendCertsFromPEM(data) {
		return nil, errors.New("invalid TLS CA")
	}
	return &tls.Config{MinVersion: tls.VersionTLS13, Certificates: []tls.Certificate{cert}, RootCAs: ca, ClientCAs: ca}, nil
}

func loadBindings() ([]policytransport.Binding, error) {
	data, err := os.ReadFile(os.Getenv("ELX_POLICY_BINDING"))
	if err != nil {
		return nil, err
	}
	var bindings []policytransport.Binding
	if err := json.Unmarshal(data, &bindings); err != nil {
		var binding policytransport.Binding
		if err := json.Unmarshal(data, &binding); err != nil {
			return nil, err
		}
		bindings = []policytransport.Binding{binding}
	}
	if err := policytransport.ValidateBindings(bindings); err != nil {
		return nil, err
	}
	return bindings, nil
}

func servePolicy(ctx context.Context, db *sql.DB) error {
	bindings, err := loadBindings()
	if err != nil {
		return err
	}
	cfg, err := transportTLS()
	if err != nil {
		return err
	}
	cfg.ClientAuth = tls.RequireAndVerifyClientCert
	addr := os.Getenv("ELX_POLICY_LISTEN")
	if addr == "" {
		return errors.New("ELX_POLICY_LISTEN is required")
	}
	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	defer listener.Close()
	server := grpc.NewServer(grpc.Creds(credentials.NewTLS(cfg)), grpc.MaxRecvMsgSize(4096))
	if err := policytransport.Register(server, db, bindings...); err != nil {
		return err
	}
	stop := context.AfterFunc(ctx, server.Stop)
	defer stop()
	err = server.Serve(listener)
	if ctx.Err() != nil {
		return nil
	}
	return err
}

func enqueuePolicy(ctx context.Context, db *sql.DB, args []string) error {
	bindings, err := loadBindings()
	if err != nil {
		return err
	}
	fs := flag.NewFlagSet("enqueue-policy", flag.ContinueOnError)
	node := fs.String("node", "", "node UUID")
	resource := fs.String("resource", "", "resource UUID")
	op := fs.String("operation", "", "stable UUID for retries")
	expected := fs.Int64("expected", -1, "expected journal revision")
	up := fs.Uint64("up", 0, "upload bytes per second")
	down := fs.Uint64("down", 0, "download bytes per second")
	disabled := fs.Bool("disabled", false, "disable subscription")
	if err := fs.Parse(args); err != nil {
		return err
	}
	id, err := uuid.Parse(*op)
	rates := policytransport.Rates{Up: *up, Down: *down, Disabled: *disabled}
	if fs.NArg() != 0 || err != nil || id == uuid.Nil || id.String() != *op || !rates.Valid() || *expected < 0 || *expected > 1<<63-3 {
		return errors.New("valid operation UUID, expected revision and positive rates required")
	}
	var target journal.Target
	if len(bindings) == 1 && *node == "" && *resource == "" {
		target = bindings[0].Target
	} else {
		for _, b := range bindings {
			if b.Target.NodeID == *node && b.Target.ResourceID == *resource {
				target = b.Target
				break
			}
		}
		if target.NodeID == "" {
			return errors.New("select a configured binding with -node and -resource")
		}
	}
	payload, err := json.Marshal(rates)
	if err != nil {
		return err
	}
	rev, err := journal.Enqueue(ctx, db, target, journal.Command{ID: *op, ExpectedRevision: *expected, Payload: payload})
	if err == nil {
		fmt.Println(rev)
	}
	return err
}

func applyPolicy(ctx context.Context) error {
	cfg, err := transportTLS()
	if err != nil {
		return err
	}
	endpoint := os.Getenv("ELX_POLICY_CONTROL")
	if endpoint == "" {
		return errors.New("ELX_POLICY_CONTROL is required")
	}
	conn, err := grpc.NewClient(endpoint, grpc.WithTransportCredentials(credentials.NewTLS(cfg)), grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(4096)))
	if err != nil {
		return err
	}
	defer conn.Close()
	core, err := openCore()
	if err != nil {
		return err
	}
	defer core.Close()
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	return policytransport.ApplyNext(ctx, conn, core)
}

func printPolicyKey(args []string) error {
	if len(args) != 1 {
		return errors.New("usage: elx-control policy-public-key SEED_FILE")
	}
	data, err := os.ReadFile(args[0])
	if err != nil {
		return err
	}
	seed, err := hex.DecodeString(string(data))
	if err != nil || len(seed) != 32 {
		return errors.New("invalid signing seed")
	}
	fmt.Println(base64.StdEncoding.EncodeToString(ed25519.NewKeyFromSeed(seed).Public().(ed25519.PublicKey)))
	return nil
}

func openCore() (*corepolicy.Client, error) {
	if addr := os.Getenv("ELXRAY_POLICY_LOOPBACK"); addr != "" {
		return corepolicy.OpenLoopback(addr)
	}
	return corepolicy.Open(os.Getenv("ELXRAY_POLICY_SOCKET"))
}

func readUsage(ctx context.Context, args []string) error {
	if len(args) != 2 {
		return errors.New("usage: elx-control read-usage SUBSCRIPTION CORE_PUBLIC_KEY")
	}
	key, err := base64.StdEncoding.DecodeString(args[1])
	if err != nil || len(key) != ed25519.PublicKeySize {
		return errors.New("invalid core public key")
	}
	core, err := openCore()
	if err != nil {
		return err
	}
	defer core.Close()
	sample, err := core.ReadUsage(ctx, args[0], key)
	if err != nil {
		return err
	}
	return json.NewEncoder(os.Stdout).Encode(sample)
}
