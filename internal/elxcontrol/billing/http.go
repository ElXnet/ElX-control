package billing

import (
 "crypto/ed25519"
 "database/sql"
 "encoding/base64"
 "encoding/json"
 "errors"
 "io"
 "net/http"
 "os"
 "strings"

 "github.com/ElXnet/ElX-control/internal/elxcontrol/policytransport"
)

func LoadVerificationKey() (ed25519.PublicKey,error) {
 path:=os.Getenv("ELX_PAYMENT_VERIFY_KEY")
 if path==""{return nil,nil}
 info,err:=os.Lstat(path)
 if err!=nil{return nil,err}
 if !info.Mode().IsRegular()||info.Mode().Perm()&0022!=0{
  return nil,errors.New("payment verifier public key must be a protected regular file")
 }
 f,err:=os.Open(path)
 if err!=nil{return nil,err}
 defer f.Close()
 data,err:=io.ReadAll(io.LimitReader(f,256))
 if err!=nil{return nil,err}
 key,err:=base64.StdEncoding.DecodeString(strings.TrimSpace(string(data)))
 if err!=nil||len(key)!=ed25519.PublicKeySize{
  return nil,errors.New("invalid payment service verification key")
 }
 return ed25519.PublicKey(key),nil
}

func respond(w http.ResponseWriter,status int,value any){
 w.Header().Set("Cache-Control","no-store")
 w.Header().Set("Content-Type","application/json; charset=utf-8")
 w.WriteHeader(status)
 _=json.NewEncoder(w).Encode(value)
}
func strictJSON(w http.ResponseWriter,r *http.Request,out any)bool{
 if !strings.HasPrefix(r.Header.Get("Content-Type"),"application/json"){
  respond(w,415,map[string]string{"error":"application/json required"});return false
 }
 r.Body=http.MaxBytesReader(w,r.Body,4096)
 decoder:=json.NewDecoder(r.Body)
 decoder.DisallowUnknownFields()
 if decoder.Decode(out)!=nil{
  respond(w,400,map[string]string{"error":"invalid request"});return false
 }
 var excess any
 if err:=decoder.Decode(&excess);!errors.Is(err,io.EOF){
  respond(w,400,map[string]string{"error":"trailing request body"});return false
 }
 return true
}
func statusCode(err error)int{
 switch{
 case errors.Is(err,ErrInvalid):return 400
 case errors.Is(err,ErrUnverified):return 403
 case errors.Is(err,ErrConflict):return 409
 case errors.Is(err,ErrNotFound):return 404
 default:return 503
 }
}

// Handler is bound ONLY to Control's 0600 Unix management socket, never
// the customer website. The payment reader is a separate service with the
// PRIVATE signing key; the panel has neither that key nor a payment API.
func Handler(db *sql.DB,public ed25519.PublicKey,
 policySource func()([]policytransport.Binding,error))http.Handler{
 mux:=http.NewServeMux()
 mux.HandleFunc("POST /billing/v1/confirmed",func(w http.ResponseWriter,r *http.Request){
  if len(public)!=ed25519.PublicKeySize{
   respond(w,503,map[string]string{"error":"payment verifier not configured"});return
  }
  var signed SignedEvent
  if !strictJSON(w,r,&signed){return}
  event,err:=Verify(public,signed)
  if err!=nil{respond(w,statusCode(err),map[string]string{"error":"payment attestation rejected"});return}
  result,err:=ApplyVerifiedPayment(r.Context(),db,event)
  if err!=nil{respond(w,statusCode(err),map[string]string{"error":"payment cannot be applied"});return}
  respond(w,200,result)
 })
 mux.HandleFunc("POST /provision/v1/claim",func(w http.ResponseWriter,r *http.Request){
  // Exactly one short-lived claim; duplicate polling never returns multiple
  // active leases for the same job. No secrets go through public panel API.
  job,err:=ClaimNext(r.Context(),db)
  if errors.Is(err,ErrNotFound) && policySource!=nil {
   // First create the profile disabled even without any policy/grant.
   // Only activation requires the trusted manifest and live core proof.
   bindings,loadErr:=policySource()
   if loadErr!=nil {
    respond(w,503,map[string]string{"error":"trusted manifest unavailable"});return
   }
   if len(bindings)>0 {
    if _,loadErr=QueueReadyEnables(r.Context(),db,bindings);loadErr!=nil{
     respond(w,503,map[string]string{"error":"profile readiness unavailable"});return
    }
   }
   job,err=ClaimNext(r.Context(),db)
  }
  if errors.Is(err,ErrNotFound){w.WriteHeader(http.StatusNoContent);return}
  if err!=nil{respond(w,statusCode(err),map[string]string{"error":"provisioning unavailable"});return}
  respond(w,200,job)
 })
 mux.HandleFunc("POST /provision/v1/ack",func(w http.ResponseWriter,r *http.Request){
  var input struct{
   JobID string `json:"jobId"`
   ClaimID string `json:"claimId"`
   Operation string `json:"operation"`
  }
  if !strictJSON(w,r,&input){return}
  status,err:=ConfirmJob(r.Context(),db,input.JobID,input.ClaimID,input.Operation)
  if err!=nil{respond(w,statusCode(err),map[string]string{"error":"provisioning acknowledgement rejected"});return}
  respond(w,200,map[string]string{"status":status})
 })
 // Never route an arbitrary caller-provided path to the privileged APIs.
 return mux
}

