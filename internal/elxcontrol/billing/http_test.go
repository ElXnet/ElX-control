package billing

import (
 "bytes"
 "crypto/ed25519"
 "encoding/json"
 "net/http"
 "net/http/httptest"
 "testing"
)

func TestPaymentIngressOnlyAcceptsSignedSettlement(t *testing.T){
 pub,_,err:=ed25519.GenerateKey(nil)
 if err!=nil{t.Fatal(err)}
 handler:=PaymentIngressHandler(nil,pub)
 for _,test:=range []struct{method,path string;want int}{
  {"GET","/billing/v1/confirmed",http.StatusMethodNotAllowed},
  {"POST","/provision/v1/claim",http.StatusNotFound},
  {"POST","/provision/v1/ack",http.StatusNotFound},
  {"GET","/v1/entitlements",http.StatusNotFound},
  {"POST","/v1/entitlements/test/fup-schedules/test/activate",http.StatusNotFound},
 }{
  r:=httptest.NewRequest(test.method,test.path,nil)
  w:=httptest.NewRecorder()
  handler.ServeHTTP(w,r)
  if w.Code!=test.want{
   t.Fatalf("%s %s: expected %d got %d",test.method,test.path,test.want,w.Code)
  }
 }
 request:=SignedEvent{Event:VerifiedEvent{
  Version:1,EventID:"00000000-0000-4000-8000-000000000001",
  OrderID:"00000000-0000-4000-8000-000000000002",
  Provider:"tester",ProviderPaymentID:"provider-id",Currency:Currency,
  AmountMinor:PriceBaseMinor,ConfirmedUnix:1000000,
 },Signature:"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=="}
 data,err:=json.Marshal(request)
 if err!=nil{t.Fatal(err)}
 r:=httptest.NewRequest("POST","/billing/v1/confirmed",bytes.NewReader(data))
 r.Header.Set("Content-Type","application/json")
 w:=httptest.NewRecorder()
 handler.ServeHTTP(w,r)
 if w.Code!=http.StatusForbidden{
  t.Fatalf("unsigned payment was accepted with HTTP %d",w.Code)
 }
}
