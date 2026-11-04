package lk

import (
 "bytes"
 "context"
 "crypto/rand"
 "encoding/hex"
 "encoding/json"
 "net/http"
 "net/http/httptest"
 "os"
 "strings"
 "testing"
 "fmt"
 "time"

 "github.com/jackc/pgx/v5"
 "github.com/jackc/pgx/v5/stdlib"
 "github.com/ElXnet/ElX-control/internal/elxcontrol/journal"
)

func testLKDatabase(t *testing.T)(context.Context,Store){
 t.Helper()
 dsn:=os.Getenv("ELX_TEST_POSTGRES_DSN")
 if dsn==""{t.Skip("ELX_TEST_POSTGRES_DSN required")}
 ctx,cancel:=context.WithTimeout(context.Background(),45*time.Second)
 t.Cleanup(cancel)
 cfg,err:=pgx.ParseConfig(dsn)
 if err!=nil{t.Fatal(err)}
 admin:=stdlib.OpenDB(*cfg)
 t.Cleanup(func(){_ = admin.Close()})
 var salt [8]byte
 if _,err=rand.Read(salt[:]);err!=nil{t.Fatal(err)}
 schema:="elx_lk_"+hex.EncodeToString(salt[:])
 if _,err=admin.ExecContext(ctx,"CREATE SCHEMA "+schema);err!=nil{t.Fatal(err)}
 t.Cleanup(func(){
  cleanup,cancel:=context.WithTimeout(context.Background(),10*time.Second)
  defer cancel()
  _,_=admin.ExecContext(cleanup,"DROP SCHEMA "+schema+" CASCADE")
 })
 cfg.RuntimeParams["search_path"]=schema
 db:=stdlib.OpenDB(*cfg)
 t.Cleanup(func(){_ = db.Close()})
 if err=journal.Migrate(ctx,db);err!=nil{t.Fatal(err)}
 return ctx,Store{DB:db}
}
func seedEntitlement(t *testing.T,ctx context.Context,store Store,id string){
 t.Helper()
 if _,err:=store.DB.ExecContext(ctx,`INSERT INTO elx_entitlements(id,active_slots,valid_until)
 VALUES($1,2,clock_timestamp()+interval '1 year')`,id);err!=nil{t.Fatal(err)}
}
func lkRequest(t *testing.T,h http.Handler,method,path string,body any,token,csrf string)*httptest.ResponseRecorder{
 t.Helper()
 var payload []byte
 if body!=nil{var err error;payload,err=json.Marshal(body);if err!=nil{t.Fatal(err)}}
 req:=httptest.NewRequest(method,path,bytes.NewReader(payload))
 if body!=nil{req.Header.Set("Content-Type","application/json")}
 if token!=""{req.AddCookie(&http.Cookie{Name:cookieName,Value:token})}
 if csrf!=""{req.Header.Set("X-ElX-CSRF",csrf)}
 w:=httptest.NewRecorder()
 h.ServeHTTP(w,req)
 return w
}
func TestLKInviteRegistrationLoginAndOwnership(t *testing.T){
 ctx,store:=testLKDatabase(t)
 e1:="00000000-0000-4000-8000-000000000061"
 e2:="00000000-0000-4000-8000-000000000062"
 seedEntitlement(t,ctx,store,e1)
 seedEntitlement(t,ctx,store,e2)
 invite,err:=store.IssueInvite(ctx,e1,72*time.Hour)
 if err!=nil{t.Fatal(err)}
 account,err:=store.Register(ctx,"Alice@example.org","correct horse safe 2026",invite)
 if err!=nil{t.Fatal(err)}
 if account.Email!="alice@example.org"||account.Token()==""||account.CSRF==""{t.Fatal("account registration incomplete")}
 if _,err:=store.Register(ctx,"Other@example.org","another safe password",invite);err!=ErrInvite{
  t.Fatalf("single-use invite reused: %v",err)
 }
 authorized,err:=store.Authenticate(ctx,account.Token())
 if err!=nil||authorized.ID!=account.ID{t.Fatalf("session invalid %+v %v",authorized,err)}
 if validCSRF(account.Token(),"wrong"){t.Fatal("forged CSRF accepted")}
 own,err:=store.Owns(ctx,account.ID,e1)
 if err!=nil||!own{t.Fatal("entitlement not owned after registration")}
 own,err=store.Owns(ctx,account.ID,e2)
 if err!=nil||own{t.Fatal("cross-entitlement access")}
 h:=Handler(store)
 denied:=lkRequest(t,h,"GET","/lk/v1/entitlements/"+e2,nil,account.Token(),"")
 if denied.Code!=401{t.Fatalf("foreign entitlement exposed %d",denied.Code)}
 noCSRF:=lkRequest(t,h,"POST","/lk/v1/logout",nil,account.Token(),"")
 if noCSRF.Code!=401{t.Fatalf("logout allowed without CSRF: %d",noCSRF.Code)}
 second,err:=store.IssueInvite(ctx,e2,72*time.Hour)
 if err!=nil{t.Fatal(err)}
 claimed,err:=store.Claim(ctx,account.ID,second)
 if err!=nil||claimed!=e2{t.Fatalf("claim: %s %v",claimed,err)}
 items,err:=store.Entitlements(ctx,account.ID)
 if err!=nil||len(items)!=2{t.Fatalf("owned items: %+v %v",items,err)}
 wrong,err:=store.Login(ctx,"alice@example.org","not the right password")
 if err!=ErrUnauthorized||wrong.Token()!=""{t.Fatalf("invalid password accepted %v",err)}
 logged,err:=store.Login(ctx,"ALICE@example.org","correct horse safe 2026")
 if err!=nil||logged.ID!=account.ID||logged.Token()==account.Token(){t.Fatalf("login %+v %v",logged,err)}
 logout:=lkRequest(t,h,"POST","/lk/v1/logout",nil,logged.Token(),logged.CSRF)
 if logout.Code!=200{t.Fatalf("logout %d %s",logout.Code,logout.Body.String())}
 if _,err:=store.Authenticate(ctx,logged.Token());err!=ErrUnauthorized{t.Fatalf("logged-out token accepted: %v",err)}
 if _,err:=store.Authenticate(ctx,account.Token());err!=nil{t.Fatalf("logout revoked other session: %v",err)}
}
func TestLKHTTPInviteCookiesAndNoSubscriptionURLAuthority(t *testing.T){
 ctx,store:=testLKDatabase(t)
 e:="00000000-0000-4000-8000-000000000071"
 seedEntitlement(t,ctx,store,e)
 invite,err:=store.IssueInvite(ctx,e,24*time.Hour)
 if err!=nil{t.Fatal(err)}
 h:=Handler(store)
 anon:=lkRequest(t,h,"GET","/lk/v1/me",nil,"","")
 if anon.Code!=401{t.Fatalf("anonymous GET allowed %d",anon.Code)}
 w:=lkRequest(t,h,"POST","/lk/v1/register",map[string]string{
  "email":"user@example.org","password":"long strong password 2026","invite":invite,
 },"","")
 if w.Code!=201 || strings.Contains(w.Body.String(),"token"){t.Fatalf("registration failed or token exposed %d %s",w.Code,w.Body.String())}
 cookies:=w.Result().Cookies()
 if len(cookies)==0{t.Fatal("session cookie missing")}
 c:=cookies[0]
 if c.Name!=cookieName||!c.Secure||!c.HttpOnly||c.SameSite!=http.SameSiteStrictMode{
  t.Fatalf("weak cookie settings: %+v",c)
 }
 w=lkRequest(t,h,"GET","/lk/v1/me",nil,c.Value,"")
 if w.Code!=200||!strings.Contains(w.Body.String(),"user@example.org"){t.Fatalf("me: %d %s",w.Code,w.Body.String())}
 if w.Header().Get("Cache-Control")!="no-store"{t.Fatal("customer data is cacheable")}
 // A subscription URL, UUID, or arbitrary Cookie is not an LK identity.
 w=lkRequest(t,h,"GET","/lk/v1/entitlements/"+e,nil,e,"")
 if w.Code!=401{t.Fatalf("subscription UUID treated as credential: %d",w.Code)}
}
func TestLKThrottlePersistsAcrossRequests(t *testing.T){
 ctx,store:=testLKDatabase(t)
 e:="00000000-0000-4000-8000-000000000081"
 seedEntitlement(t,ctx,store,e)
 invite,err:=store.IssueInvite(ctx,e,24*time.Hour)
 if err!=nil{t.Fatal(err)}
 _,err=store.Register(ctx,"throttle@example.org","long correct secret",invite)
 if err!=nil{t.Fatal(err)}
 for i:=0;i<5;i++{
  if _,err=store.Login(ctx,"throttle@example.org","wrong password");err!=ErrUnauthorized{t.Fatalf("invalid #%d: %v",i,err)}
 }
 if _,err=store.Login(ctx,"throttle@example.org","long correct secret");err!=ErrThrottle{
  t.Fatalf("correct password bypassed database throttle: %v",err)
 }
}

func TestLKFUPRequiresCSRFAndLimitsUserSchedules(t *testing.T){
 ctx,store:=testLKDatabase(t)
 entitlement:="00000000-0000-4000-8000-000000000091"
 seedEntitlement(t,ctx,store,entitlement)
 if _,err:=store.DB.ExecContext(ctx,`INSERT INTO elx_rate_budgets
  (entitlement_id,up_limit,down_limit) VALUES($1,12500000,12500000)`,entitlement);err!=nil{t.Fatal(err)}
 invite,err:=store.IssueInvite(ctx,entitlement,24*time.Hour)
 if err!=nil{t.Fatal(err)}
 account,err:=store.Register(ctx,"fup@example.org","strong password 2026",invite)
 if err!=nil{t.Fatal(err)}
 h:=Handler(store)
 path:="/lk/v1/entitlements/"+entitlement+"/fup-schedules"
 for i:=0;i<4;i++{
  spec:=map[string]any{"scheduleId":fmt.Sprintf("00000000-0000-4000-8000-%012d",200+i),
   "cadence":"day","timezone":"UTC","direction":"total","thresholdBytes":1000000,
   "reducedUp":2500000,"reducedDown":2500000}
  if i==0{
   w:=lkRequest(t,h,"POST",path,spec,account.Token(),"")
   if w.Code!=401{t.Fatalf("CSRF bypass: %d",w.Code)}
  }
  w:=lkRequest(t,h,"POST",path,spec,account.Token(),account.CSRF)
  if i<3 && w.Code!=201{t.Fatalf("schedule %d: %d %s",i,w.Code,w.Body.String())}
  if i==3 && w.Code!=400{t.Fatalf("user schedule quota bypass %d %s",w.Code,w.Body.String())}
  if i==0{
   replay:=lkRequest(t,h,"POST",path,spec,account.Token(),account.CSRF)
   if replay.Code!=200{t.Fatalf("idempotent retry: %d %s",replay.Code,replay.Body.String())}
  }
 }
}
