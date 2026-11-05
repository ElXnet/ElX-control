package main

import (
	"context"
	"crypto/ed25519"
	"crypto/tls"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/google/uuid"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/fencetransport"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/session"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

func parseDrainProfile(args []string) (session.Fence,error) {
	var f session.Fence
	fs:=flag.NewFlagSet("drain-profile",flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	var owner,profile,node,incarnation string
	fs.StringVar(&owner,"owner","","reserved session owner UUID")
	fs.StringVar(&profile,"profile","","authenticated VLESS profile/account UUID")
	fs.StringVar(&node,"node","","trusted node UUID")
	fs.StringVar(&incarnation,"incarnation","","running core UUID")
	fs.Int64Var(&f.Generation,"generation",0,"occupied slot generation")
	if fs.Parse(args)!=nil || fs.NArg()!=0 || f.Generation<=0 {
		return session.Fence{},errors.New("drain-profile requires owner,profile,node,incarnation,generation")
	}
	for i,raw:=range []string{owner,profile,node,incarnation} {
		id,err:=uuid.Parse(raw)
		if err!=nil || id==uuid.Nil || id.String()!=raw {return session.Fence{},errors.New("canonical nonzero profile drain UUIDs required")}
		switch i {
		case 0:f.OwnerID=id
		case 1:f.ProfileID=id
		case 2:f.NodeID=id
		case 3:f.Incarnation=id
		}
	}
	return f,nil
}

// drainProfile is a privileged supervisor command, not an endpoint exposed to
// subscribers. It uses the provisioned core key and node mTLS identity, never
// a public key or node authentication assertion from an end-user.
func drainProfile(ctx context.Context,args []string) error {
	f,err:=parseDrainProfile(args)
	if err!=nil {return err}
	bindings,err:=loadBindings()
	if err!=nil {return err}
	var pinned ed25519.PublicKey
	for _,binding:=range bindings {
		if binding.Target.NodeID==f.NodeID.String() {
			pinned=append(ed25519.PublicKey(nil),binding.PublicKey...)
			break
		}
	}
	if len(pinned)!=ed25519.PublicKeySize {
		return errors.New("node has no provisioned core identity binding")
	}
	core,err:=openCore()
	if err!=nil {return err}
	defer core.Close()

	// ElXray can sign only AFTER durable denial and actual tracked flow drain.
	signature,err:=core.DrainProfile(ctx,f,pinned)
	if err!=nil {return fmt.Errorf("ElXray profile drain not completed: %w",err)}

	cfg,err:=transportTLS()
	if err!=nil {return err}
	cfg.MinVersion=tls.VersionTLS13
	target:=os.Getenv("ELX_POLICY_CONTROL")
	if target=="" {return errors.New("ELX_POLICY_CONTROL is required")}
	conn,err:=grpc.NewClient(target,grpc.WithTransportCredentials(credentials.NewTLS(cfg)),
		grpc.WithDefaultCallOptions(grpc.MaxCallRecvMsgSize(4096)))
	if err!=nil {return err}
	defer conn.Close()
	if err:=fencetransport.Send(ctx,conn,f,signature);err!=nil {
		// Denial remains persisted at the core. Safe to retry this command
		// with the same fence after a lost network ACK.
		return fmt.Errorf("session fence delivery failed (profile stays denied): %w",err)
	}
	return json.NewEncoder(os.Stdout).Encode(map[string]any{
		"owner":f.OwnerID,"profile":f.ProfileID,"generation":f.Generation,"released":true,
	})
}
