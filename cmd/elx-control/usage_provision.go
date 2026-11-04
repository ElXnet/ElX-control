package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"

	"github.com/ElXnet/ElX-control/internal/elxcontrol/management"
)

func provisionUsage(ctx context.Context,db *sql.DB,args []string)error{
	var entitlement string
	var spec management.UsageProvision
	fs:=flag.NewFlagSet("provision-usage",flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&entitlement,"entitlement","","purchased entitlement UUID")
	fs.StringVar(&spec.ScheduleID,"schedule","","FUP schedule UUID")
	fs.StringVar(&spec.NodeID,"node","","authenticated node UUID")
	fs.StringVar(&spec.ResourceID,"resource","","purchased rate-grant resource UUID")
	fs.StringVar(&spec.ExecutorID,"executor","","trusted executor UUID")
	fs.StringVar(&spec.Incarnation,"incarnation","","pinned ElXray boot UUID")
	fs.StringVar(&spec.AccountingID,"accounting","","durable signed usage stream UUID")
	fs.Int64Var(&spec.Generation,"generation",1,"accounting stream generation")
	fs.StringVar(&spec.SubscriptionID,"subscription","","trusted ElXray subscription ID")
	if err:=fs.Parse(args);err!=nil{return err}
	if fs.NArg()!=0||entitlement==""{return errors.New("provision-usage requires an entitlement and full trusted stream binding")}
	result,err:=(management.SQLStore{DB:db}).ProvisionUsageStream(ctx,entitlement,spec)
	if err!=nil{return fmt.Errorf("provision signed usage: %w",err)}
	// This output is NOT a bearer token. Deploy Binding only to the identified
	// node's trusted ELX_USAGE_BINDINGS file, with filesystem permissions 0600.
	return json.NewEncoder(os.Stdout).Encode(result)
}

func usageCoverage(ctx context.Context,db *sql.DB,args []string)error{
	var entitlement,schedule string
	fs:=flag.NewFlagSet("usage-coverage",flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&entitlement,"entitlement","","purchased entitlement UUID")
	fs.StringVar(&schedule,"schedule","","FUP schedule UUID")
	if err:=fs.Parse(args);err!=nil{return err}
	if fs.NArg()!=0||entitlement==""||schedule==""{return errors.New("usage-coverage requires -entitlement and -schedule")}
	result,err:=(management.SQLStore{DB:db}).UsageCoverage(ctx,entitlement,schedule)
	if err!=nil{return err}
	return json.NewEncoder(os.Stdout).Encode(result)
}

func activateFUP(ctx context.Context,db *sql.DB,args []string)error{
	var entitlement,schedule string
	fs:=flag.NewFlagSet("activate-fup",flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	fs.StringVar(&entitlement,"entitlement","","purchased entitlement UUID")
	fs.StringVar(&schedule,"schedule","","staged FUP schedule UUID")
	if err:=fs.Parse(args);err!=nil{return err}
	if fs.NArg()!=0||entitlement==""||schedule==""{return errors.New("activate-fup requires -entitlement and -schedule")}
	result,err:=(management.SQLStore{DB:db}).ActivateSchedule(ctx,entitlement,schedule)
	if err!=nil{return fmt.Errorf("activate signed FUP schedule: %w",err)}
	return json.NewEncoder(os.Stdout).Encode(result)
}

 // autoProvisionUsage reads the same trusted policy manifest as serve-policy,
 // so a subscription/resource pair is never typed separately by an operator.
func autoProvisionUsage(ctx context.Context,db *sql.DB,args []string)error{
	fs:=flag.NewFlagSet("auto-provision-usage",flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	entitlement:=fs.String("entitlement","","purchased entitlement UUID")
	schedule:=fs.String("schedule","","FUP schedule UUID")
	if err:=fs.Parse(args);err!=nil{return err}
	if fs.NArg()!=0||*entitlement==""||*schedule=="" {
		return errors.New("auto-provision-usage requires -entitlement and -schedule")
	}
	bindings,err:=loadBindings()
	if err!=nil{return fmt.Errorf("trusted policy manifest unavailable: %w",err)}
	result,err:=(management.SQLStore{DB:db}).AutoProvisionFromBindings(
		ctx,*entitlement,*schedule,bindings)
	if err!=nil{return fmt.Errorf("automatic signed usage enrollment failed: %w",err)}
	return json.NewEncoder(os.Stdout).Encode(result)
}
