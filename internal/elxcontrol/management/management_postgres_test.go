package management

import (
 "context"
 "crypto/rand"
 "database/sql"
 "encoding/hex"
 "errors"
 "os"
 "testing"
 "time"

 "github.com/jackc/pgx/v5"
 "github.com/jackc/pgx/v5/stdlib"
 "github.com/ElXnet/ElX-control/internal/elxcontrol/journal"
)

func managementPostgres(t *testing.T)(context.Context,*sql.DB){
 t.Helper()
 dsn:=os.Getenv("ELX_TEST_POSTGRES_DSN")
 if dsn==""{t.Skip("ELX_TEST_POSTGRES_DSN not set")}
 ctx,cancel:=context.WithTimeout(context.Background(),20*time.Second)
 t.Cleanup(cancel)
 cfg,err:=pgx.ParseConfig(dsn)
 if err!=nil{t.Fatal(err)}
 admin:=stdlib.OpenDB(*cfg)
 t.Cleanup(func(){admin.Close()})
 var suffix [8]byte
 if _,err=rand.Read(suffix[:]);err!=nil{t.Fatal(err)}
 schema:="elx_mgmt_"+hex.EncodeToString(suffix[:])
 if _,err=admin.ExecContext(ctx,"CREATE SCHEMA "+schema);err!=nil{t.Fatal(err)}
 t.Cleanup(func(){
  ctx,cancel:=context.WithTimeout(context.Background(),10*time.Second)
  defer cancel()
  _,_ = admin.ExecContext(ctx,"DROP SCHEMA "+schema+" CASCADE")
 })
 cfg.RuntimeParams["search_path"]=schema
 db:=stdlib.OpenDB(*cfg)
 t.Cleanup(func(){db.Close()})
 if err=journal.Migrate(ctx,db);err!=nil{t.Fatal(err)}
 return ctx,db
}
func TestManagementPostgresPaginationAndOwnership(t *testing.T){
 ctx,db:=managementPostgres(t)
 first:="00000000-0000-4000-8000-000000000001"
 second:="00000000-0000-4000-8000-000000000002"
 dev:="00000000-0000-4000-8000-000000000003"
 for _,id:=range []string{first,second}{
  if _,err:=db.ExecContext(ctx,"INSERT INTO elx_entitlements(id,active_slots,valid_until) VALUES($1,2,clock_timestamp()+interval '1 day')",id);err!=nil{t.Fatal(err)}
 }
 if _,err:=db.ExecContext(ctx,"INSERT INTO elx_devices(id,entitlement_id,key_generation) VALUES ($1,$2,1)",dev,first);err!=nil{t.Fatal(err)}
 if _,err:=db.ExecContext(ctx,"INSERT INTO elx_rate_budgets(entitlement_id,up_limit,down_limit) VALUES($1,12500000,25000000)",first);err!=nil{t.Fatal(err)}
 store:=SQLStore{DB:db}
 page,err:=store.List(ctx,"",1)
 if err!=nil||len(page.Items)!=1||page.Items[0].ID!=first||page.NextCursor!=first{t.Fatalf("first page: %+v %v",page,err)}
 page,err=store.List(ctx,first,1)
 if err!=nil||len(page.Items)!=1||page.Items[0].ID!=second||page.NextCursor!=""{t.Fatalf("second page: %+v %v",page,err)}
 detail,err:=store.Get(ctx,first)
 if err!=nil{t.Fatal(err)}
 if len(detail.Devices)!=1||detail.Devices[0].ID!=dev||detail.RateBudget==nil||detail.RateBudget.Up!=12500000{
  t.Fatalf("incorrect join data %+v",detail)
 }
 if err:=store.QueueDrain(ctx,second,"00000000-0000-4000-8000-000000000004");!errors.Is(err,ErrNotFound){
  t.Fatalf("cross-entitlement/unknown owner was not rejected: %v",err)
 }
 if _,err=store.Get(ctx,"00000000-0000-4000-8000-000000000099");!errors.Is(err,ErrNotFound){
  t.Fatalf("missing entitlement: %v",err)
 }
}
