package billing

import (
 "context"
 "crypto/ed25519"
 "crypto/rand"
 "database/sql"
 "encoding/hex"
 "errors"
 "os"
 "testing"
 "time"

 "github.com/ElXnet/ElX-control/internal/elxcontrol/journal"
 "github.com/google/uuid"
 "github.com/jackc/pgx/v5"
 "github.com/jackc/pgx/v5/stdlib"
)

func billingPostgres(t *testing.T)(context.Context,*sql.DB){
 t.Helper()
 dsn:=os.Getenv("ELX_TEST_POSTGRES_DSN")
 if dsn==""{t.Skip("ELX_TEST_POSTGRES_DSN unset")}
 ctx,cancel:=context.WithTimeout(context.Background(),40*time.Second)
 t.Cleanup(cancel)
 cfg,err:=pgx.ParseConfig(dsn)
 if err!=nil{t.Fatal(err)}
 admin:=stdlib.OpenDB(*cfg);t.Cleanup(func(){admin.Close()})
 var seed [8]byte
 if _,err:=rand.Read(seed[:]);err!=nil{t.Fatal(err)}
 schema:="elx_billing_"+hex.EncodeToString(seed[:])
 if _,err=admin.ExecContext(ctx,"CREATE SCHEMA "+schema);err!=nil{t.Fatal(err)}
 t.Cleanup(func(){
  cleanupCtx,cancel:=context.WithTimeout(context.Background(),10*time.Second)
  defer cancel()
  _,_ = admin.ExecContext(cleanupCtx,"DROP SCHEMA "+schema+" CASCADE")
 })
 cfg.RuntimeParams["search_path"]=schema
 db:=stdlib.OpenDB(*cfg);t.Cleanup(func(){db.Close()})
 if err=journal.Migrate(ctx,db);err!=nil{t.Fatal(err)}
 return ctx,db
}

func billingAccount(t *testing.T,ctx context.Context,db *sql.DB)string{
 t.Helper()
 id:=uuid.NewString()
 _,err:=db.ExecContext(ctx,`INSERT INTO elx_lk_accounts
  (id,email,password_salt,password_hash,password_iterations)
  VALUES($1,$2,$3,$4,600000)`,id,
  "test-"+id+"@example.test",make([]byte,16),make([]byte,32))
 if err!=nil{t.Fatal(err)}
 return id
}
func confirmed(t *testing.T,order Order,pub ed25519.PublicKey,secret ed25519.PrivateKey)(SignedEvent){
 t.Helper()
 _=pub
 event:=VerifiedEvent{Version:1,EventID:uuid.NewString(),OrderID:order.ID,
  Provider:"test-verifier",ProviderPaymentID:uuid.NewString(),
  AmountMinor:order.AmountMinor,Currency:Currency,
  ConfirmedUnix:time.Now().UTC().Unix()}
 signed,err:=SignForVerifier(event,secret)
 if err!=nil{t.Fatal(err)}
 return signed
}

func TestVerifiedPaymentCreatesPaidRightsAndIdempotentProfile(t *testing.T){
 ctx,db:=billingPostgres(t)
 account:=billingAccount(t,ctx,db)
 order,err:=CreateOrder(ctx,db,account,uuid.NewString(),"",2)
 if err!=nil{t.Fatal(err)}
 if order.AmountMinor!=90000||order.Currency!="RUB"{t.Fatalf("wrong server tariff: %+v",order)}
 same,err:=CreateOrder(ctx,db,account,order.RequestID,"",2)
 if err!=nil||same!=order{t.Fatalf("checkout replay changed purchase: %+v %+v %v",same,order,err)}
 if _,err=CreateOrder(ctx,db,account,order.RequestID,"",1);!errors.Is(err,ErrConflict){
  t.Fatalf("changed idempotency key parameters accepted: %v",err)
 }
 public,private,err:=ed25519.GenerateKey(nil)
 if err!=nil{t.Fatal(err)}
 signed:=confirmed(t,order,public,private)
 forged:=signed
 forged.Event.AmountMinor=50000
 if _,err=ApplySignedPayment(ctx,db,forged,public);!errors.Is(err,ErrUnverified){
  t.Fatalf("tampered attestation accepted: %v",err)
 }
 missingKey:=make(ed25519.PublicKey,ed25519.PublicKeySize)
 if _,err=ApplySignedPayment(ctx,db,signed,missingKey);!errors.Is(err,ErrUnverified){
  t.Fatalf("untrusted payment verifier accepted: %v",err)
 }
 applied,err:=ApplySignedPayment(ctx,db,signed,public)
 if err!=nil||applied.EntitlementID==""||applied.ProfileID==""||applied.AlreadyApplied{
  t.Fatalf("verified payment did not credit exactly once: %+v %v",applied,err)
 }
 var slots,up,down int64
 var until time.Time
 err=db.QueryRowContext(ctx,`SELECT e.active_slots,e.valid_until,b.up_limit,b.down_limit
  FROM elx_entitlements e JOIN elx_rate_budgets b ON b.entitlement_id=e.id
  WHERE e.id=$1`,applied.EntitlementID).Scan(&slots,&until,&up,&down)
 if err!=nil||slots!=4||up!=DefaultBudgetBytesPerSecond||
  down!=DefaultBudgetBytesPerSecond||until.Before(time.Now().Add(29*24*time.Hour)){
  t.Fatalf("paid entitlement invalid: slots=%d speed=%d/%d until=%v err=%v",slots,up,down,until,err)
 }
 var owners,receipts,jobs int
 for _,query:=range []struct{sql string;out *int}{
  {`SELECT count(*) FROM elx_lk_ownership WHERE account_id=$1`,&owners},
  {`SELECT count(*) FROM elx_payment_receipts WHERE order_id=$1`,&receipts},
  {`SELECT count(*) FROM elx_profile_provision_jobs`,&jobs},
 }{
  param:=any(applied.EntitlementID)
  if query.out==&owners{param=account}
  if query.out==&receipts{param=order.ID}
  if query.out==&jobs{
    err=db.QueryRowContext(ctx,query.sql).Scan(query.out)
   }else{
    err=db.QueryRowContext(ctx,query.sql,param).Scan(query.out)
   }
   if err!=nil{t.Fatal(err)}
 }
 if owners!=1||receipts!=1||jobs!=1{t.Fatalf("duplicate rights: %d %d %d",owners,receipts,jobs)}
 again,err:=ApplySignedPayment(ctx,db,signed,public)
 if err!=nil||!again.AlreadyApplied||again.EntitlementID!=applied.EntitlementID{
  t.Fatalf("replayed payment gave new access: %+v %v",again,err)
 }
 if _,err=ApplySignedPayment(ctx,db,SignedEvent{Event:VerifiedEvent{
   Version:1,EventID:uuid.NewString(),OrderID:order.ID,
   Provider:signed.Event.Provider,ProviderPaymentID:signed.Event.ProviderPaymentID,
   AmountMinor:order.AmountMinor,Currency:Currency,ConfirmedUnix:signed.Event.ConfirmedUnix,
  },Signature:signed.Signature},public);!errors.Is(err,ErrUnverified){
  t.Fatalf("changed signed event ID accepted: %v",err)
 }

 // New event with the same provider transaction cannot fund a second order.
 other,err:=CreateOrder(ctx,db,account,uuid.NewString(),"",2)
 if err!=nil{t.Fatal(err)}
 stolen:=signed.Event;stolen.OrderID=other.ID;stolen.EventID=uuid.NewString()
 double,err:=SignForVerifier(stolen,private)
 if err!=nil{t.Fatal(err)}
 if _,err=ApplySignedPayment(ctx,db,double,public);!errors.Is(err,ErrConflict){
  t.Fatalf("one bank transaction paid two orders: %v",err)
 }

 // The paid profile starts disabled; its outbox claim is exactly replayable.
 job,err:=ClaimNext(ctx,db)
 if err!=nil||job.Operation!="create-disabled"||job.VLESSID==""||
  job.ProfileID!=applied.ProfileID{t.Fatalf("disabled profile job: %+v %v",job,err)}
 if _,err=ConfirmJob(ctx,db,job.JobID,uuid.NewString(),job.Operation);!errors.Is(err,ErrConflict){
  t.Fatalf("wrong worker token acknowledged profile: %v",err)
 }
 if state,err:=ConfirmJob(ctx,db,job.JobID,job.ClaimID,job.Operation);
  err!=nil||state!="staged"{t.Fatalf("disabled profile not staged: %s %v",state,err)}
 if _,err=ClaimNext(ctx,db);!errors.Is(err,ErrNotFound){
  t.Fatalf("staged profile was reprovisioned: %v",err)
 }
}

func TestVerifiedRenewalPreservesProfileAndQueuesExpiry(t *testing.T){
 ctx,db:=billingPostgres(t)
 acct:=billingAccount(t,ctx,db)
 pub,priv,err:=ed25519.GenerateKey(nil)
 if err!=nil{t.Fatal(err)}
 initial,err:=CreateOrder(ctx,db,acct,uuid.NewString(),"",0)
 if err!=nil{t.Fatal(err)}
 first,err:=ApplySignedPayment(ctx,db,confirmed(t,initial,pub,priv),pub)
 if err!=nil{t.Fatal(err)}
 var before time.Time
 if err=db.QueryRowContext(ctx,`SELECT valid_until FROM elx_entitlements WHERE id=$1`,
  first.EntitlementID).Scan(&before);err!=nil{t.Fatal(err)}
 renew,err:=CreateOrder(ctx,db,acct,uuid.NewString(),first.EntitlementID,1)
 if err!=nil{t.Fatal(err)}
 if renew.AmountMinor!=70000{t.Fatal("addon price mismatch")}
 confirmedEvent:=confirmed(t,renew,pub,priv)
 after,err:=ApplySignedPayment(ctx,db,confirmedEvent,pub)
 if err!=nil||after.ProfileID!=first.ProfileID{t.Fatalf("renewal changed profile: %+v %v",after,err)}
 var newUntil time.Time
 var slots int
 if err=db.QueryRowContext(ctx,`SELECT valid_until,active_slots FROM elx_entitlements
  WHERE id=$1`,first.EntitlementID).Scan(&newUntil,&slots);err!=nil{t.Fatal(err)}
 if slots!=3||newUntil.Sub(before)<29*24*time.Hour{t.Fatalf("renewal did not extend or adjust rights: %d %v",slots,newUntil.Sub(before))}
 job,err:=ClaimNext(ctx,db)
 if err!=nil{t.Fatal(err)}
 if _,err=ConfirmJob(ctx,db,job.JobID,job.ClaimID,"create-disabled");err!=nil{t.Fatal(err)}
 refresh,err:=ClaimExpiryRefresh(ctx,db)
 if err!=nil||refresh.Operation!="renew-expiry"||refresh.ValidUntil.Before(newUntil.Add(-time.Second)){
  t.Fatalf("paid expiry update unavailable: %+v %v",refresh,err)
 }
 if err=ConfirmExpiryRefresh(ctx,db,refresh.JobID,uuid.NewString());!errors.Is(err,ErrConflict){t.Fatalf("foreign ack accepted: %v",err)}
 if err=ConfirmExpiryRefresh(ctx,db,refresh.JobID,refresh.ClaimID);err!=nil{t.Fatal(err)}
 if _,err=ClaimExpiryRefresh(ctx,db);!errors.Is(err,ErrNotFound){t.Fatalf("renewal job replayed: %v",err)}
 dup,err:=ApplySignedPayment(ctx,db,confirmedEvent,pub)
 if err!=nil||!dup.AlreadyApplied{t.Fatalf("renewal replay: %+v %v",dup,err)}
 var replayUntil time.Time
 if err=db.QueryRowContext(ctx,"SELECT valid_until FROM elx_entitlements WHERE id=$1",first.EntitlementID).Scan(&replayUntil);err!=nil{t.Fatal(err)}
 if !replayUntil.Equal(newUntil){t.Fatalf("renewal replay extended entitlement twice")}
}
