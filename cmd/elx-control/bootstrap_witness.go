package main

import (
 "context"
 "database/sql"
 "errors"
 "flag"
 "fmt"

 "github.com/ElXnet/ElX-control/internal/elxcontrol/journal"
)

// bootstrapStoreWitness is a privileged OFFLINE step, not an RPC, never
// called by serve-agent. The operator MUST inspect the stopped core's
// immutable state and signed baseline before authorizing first registration.
func bootstrapStoreWitness(ctx context.Context,db *sql.DB,args []string) error {
 bindings,err:=loadBindings();if err!=nil{return err}
 fs:=flag.NewFlagSet("bootstrap-store-witness",flag.ContinueOnError)
 node:=fs.String("node","","assigned node UUID")
 resource:=fs.String("resource","","assigned resource UUID")
 executor:=fs.String("executor","","pinned executor UUID")
 store:=fs.String("store","","new immutable journal store UUID")
 epoch:=fs.Uint64("epoch",0,"Control grant generation")
 revision:=fs.Uint64("core-revision",0,"core snapshot revision verified offline")
 approval:=fs.String("approve","","operator confirmation: ACK_OFFLINE_CORE_BASELINE")
 if err:=fs.Parse(args);err!=nil{return err}
 if fs.NArg()!=0 || *approval!="ACK_OFFLINE_CORE_BASELINE" {
  return errors.New("explicit offline baseline approval required; automatic first-use store bootstrap is forbidden")
 }
 var selected bool
 for _,b:=range bindings {
  if b.Target.NodeID==*node && b.Target.ResourceID==*resource &&
   b.ExecutorID==*executor && b.Epoch>0 && uint64(b.Epoch)==*epoch {
   selected=true;break
  }
 }
 if !selected {return errors.New("store bootstrap differs from the current trusted Control binding")}
 w:=journal.CoreStoreWitness{NodeID:*node,ResourceID:*resource,ExecutorID:*executor,
  StoreID:*store,AuthorityGeneration:*epoch,CoreRevision:*revision}
 if err:=journal.ProvisionCoreStoreWitness(ctx,db,w);err!=nil{return err}
 fmt.Printf("approved persistent Control store witness: %s\n",w.String())
 return nil
}
