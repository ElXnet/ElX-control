package main

import (
 "context"
 "database/sql"
 "errors"
 "flag"
 "fmt"
 "os"
 "time"

 "github.com/ElXnet/ElX-control/internal/elxcontrol/lk"
)

// The invitation is returned once by the trusted local command and never
// persisted as plaintext. Do not forward its output to logs or chats.
func issueInvite(ctx context.Context,db *sql.DB,args []string)error{
 fs:=flag.NewFlagSet("issue-invite",flag.ContinueOnError)
 fs.SetOutput(os.Stderr)
 entitlement:=fs.String("entitlement","","purchased entitlement UUID")
 ttl:=fs.Duration("ttl",72*time.Hour,"invitation validity (1h..30d)")
 if err:=fs.Parse(args);err!=nil{return err}
 if fs.NArg()!=0||*entitlement==""{return errors.New("issue-invite requires -entitlement UUID")}
 token,err:=(lk.Store{DB:db}).IssueInvite(ctx,*entitlement,*ttl)
 if err!=nil{return err}
 fmt.Println(token)
 return nil
}
