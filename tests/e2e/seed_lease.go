// Command seed-lease provisions disposable loopback E2E rate grants.
// This executable is test-only and is never part of elx-control's CLI.
package main

import (
    "context"
    "database/sql"
    "encoding/base64"
    "errors"
    "fmt"
    "os"
    "time"

    _ "github.com/jackc/pgx/v5/stdlib"
    "github.com/google/uuid"
)

func seed(ctx context.Context, db *sql.DB, args []string) error {
    if len(args)!=8 {return errors.New("usage: entitlement resource node0 incarnation0 coreKey0 node1 incarnation1 coreKey1")}
    ids:=[]int{0,1,2,3,5,6}
    for _,i:=range ids {
        id,e:=uuid.Parse(args[i])
        if e!=nil||id==uuid.Nil||id.String()!=args[i]{return errors.New("invalid canonical UUID")}
    }
    keys:=make([][]byte,2)
    for j,i:=range []int{4,7} {
        raw,e:=base64.StdEncoding.DecodeString(args[i])
        if e!=nil||len(raw)!=32{return errors.New("invalid core public key")}
        keys[j]=raw
    }
    tx,e:=db.BeginTx(ctx,nil)
    if e!=nil{return e}
    defer tx.Rollback()
    _,e=tx.ExecContext(ctx,`INSERT INTO elx_entitlements(id,active_slots,valid_until)
        VALUES($1,2,clock_timestamp()+interval '1 hour')`,args[0])
    if e!=nil{return e}
    _,e=tx.ExecContext(ctx,`INSERT INTO elx_rate_budgets(entitlement_id,up_limit,down_limit)
        VALUES($1,500000,500000)`,args[0])
    if e!=nil{return e}
    for j,offset:=range []int{2,5} {
        node,inc:=args[offset],args[offset+1]
        _,e=tx.ExecContext(ctx,`INSERT INTO elx_operation_targets(node_id,resource_id)
            VALUES($1,$2)`,node,args[1])
        if e!=nil{return e}
        _,e=tx.ExecContext(ctx,`INSERT INTO elx_core_identities(node_id,incarnation,public_key)
            VALUES($1,$2,$3)`,node,inc,keys[j])
        if e!=nil{return e}
        _,e=tx.ExecContext(ctx,`INSERT INTO elx_rate_grants
            (entitlement_id,node_id,resource_id,committed_up,committed_down,epoch,barrier_public_key)
            VALUES($1,$2,$3,250000,250000,1,$4)`,
            args[0],node,args[1],keys[j])
        if e!=nil{return e}
    }
    return tx.Commit()
}

func main(){
    dsn:=os.Getenv("ELX_CONTROL_POSTGRES_DSN")
    if dsn=="" {fmt.Fprintln(os.Stderr,"test-only PostgreSQL DSN is required");os.Exit(1)}
    db,e:=sql.Open("pgx",dsn)
    if e!=nil{fmt.Fprintln(os.Stderr,e);os.Exit(1)}
    defer db.Close()
    ctx,cancel:=context.WithTimeout(context.Background(),15*time.Second)
    defer cancel()
    if e=seed(ctx,db,os.Args[1:]);e!=nil{fmt.Fprintln(os.Stderr,e);os.Exit(1)}
    fmt.Println("PASS: disposable signed Control lease fixture provisioned")
}
