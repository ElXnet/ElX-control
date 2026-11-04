package main

import (
 "context"
 "crypto/ed25519"
 "database/sql"
 "encoding/base64"
 "encoding/json"
 "errors"
 "flag"
 "fmt"
 "os"
 "strings"

 "github.com/ElXnet/ElX-control/internal/elxcontrol/journal"
)

func readPinnedCorePublicKey(path string)(ed25519.PublicKey,error){
 if path==""{return nil,errors.New("new ElXray public key file required")}
 stat,err:=os.Lstat(path)
 if err!=nil{return nil,err}
 if !stat.Mode().IsRegular()||stat.Mode().Perm()&0022!=0{
  return nil,errors.New("core public key must be a protected regular file")
 }
 data,err:=os.ReadFile(path)
 if err!=nil{return nil,err}
 if len(data)>256{return nil,errors.New("core public key too long")}
 value,err:=base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
 if err!=nil||len(value)!=ed25519.PublicKeySize{
  return nil,errors.New("invalid new core Ed25519 public key")
 }
 return ed25519.PublicKey(value),nil
}

func beginCoreRotation(ctx context.Context,db *sql.DB,args []string)error{
 fs:=flag.NewFlagSet("begin-core-rotation",flag.ContinueOnError)
 fs.SetOutput(os.Stderr)
	id:=fs.String("rotation","","stable rotation UUID")
	node:=fs.String("node","","node UUID")
	old:=fs.String("old","","registered old core incarnation UUID")
	next:=fs.String("new","","new core incarnation UUID")
	keyFile:=fs.String("new-public-key","","protected new core Ed25519 key file")
	if err:=fs.Parse(args);err!=nil{return err}
	if fs.NArg()!=0{return errors.New("unexpected rotation arguments")}
	public,err:=readPinnedCorePublicKey(*keyFile)
	if err!=nil{return err}
	result,err:=journal.BeginCoreRotation(ctx,db,*id,*node,*old,*next,public)
	if err!=nil{return fmt.Errorf("cannot begin fail-closed core rotation: %w",err)}
	return json.NewEncoder(os.Stdout).Encode(result)
}

func completeCoreRotation(ctx context.Context,db *sql.DB,args []string)error{
 fs:=flag.NewFlagSet("complete-core-rotation",flag.ContinueOnError)
 fs.SetOutput(os.Stderr)
	id:=fs.String("rotation","","previously opened rotation UUID")
	if err:=fs.Parse(args);err!=nil{return err}
	if fs.NArg()!=0{return errors.New("unexpected rotation arguments")}
	result,err:=journal.CompleteCoreRotation(ctx,db,*id)
	if err!=nil{return fmt.Errorf("cannot complete signed core cutover: %w",err)}
	return json.NewEncoder(os.Stdout).Encode(result)
}

// Queue-rate-move reuses the existing durable signed policy delivery and
// core-signed rate-barrier protocol, not a private rotation-specific bypass.
func queueRateMove(ctx context.Context,db *sql.DB,args []string)error{
 fs:=flag.NewFlagSet("queue-rate-move",flag.ContinueOnError)
 fs.SetOutput(os.Stderr)
	ent:=fs.String("entitlement","","purchased entitlement UUID")
	node:=fs.String("node","","node UUID")
	resource:=fs.String("resource","","rate grant resource UUID")
	op:=fs.String("operation","","stable operation UUID")
	expected:=fs.Int64("expected",0,"current policy journal revision")
	up:=fs.Int64("up",0,"desired upload bytes/sec (0 when draining)")
	down:=fs.Int64("down",0,"desired download bytes/sec (0 when draining)")
	if err:=fs.Parse(args);err!=nil{return err}
	if fs.NArg()!=0{return errors.New("unexpected rate move arguments")}
	id,err:=journal.QueueRateMove(ctx,db,*ent,
		journal.Target{NodeID:*node,ResourceID:*resource},*op,*expected,
		journal.Rate{Up:*up,Down:*down})
	if err!=nil{return err}
	return json.NewEncoder(os.Stdout).Encode(map[string]int64{"revision":id})
}
