// Package billing accepts payment *attestations* from an independent verifier.
// It never contacts banks, reads SMS, or marks a payment successful on behalf
// of a client. Only Control may grant entitlements and queue VPN provisioning.
package billing

import (
 "context"
 "crypto/ed25519"
 "crypto/sha256"
 "database/sql"
 "encoding/base64"
 "errors"
 "fmt"
 "regexp"
 "strings"
 "time"

 "github.com/google/uuid"
)

var (
 ErrInvalid=errors.New("invalid checkout or verified payment input")
 ErrConflict=errors.New("payment, order, or entitlement conflict")
 ErrUnverified=errors.New("external payment verification signature invalid")
 ErrNotFound=errors.New("order not found")
)
const (
 Currency="RUB"
 PriceBaseMinor=50000 // 500 rubles
 PricePerExtraMinor=20000 // +200 rubles for each of up to 2 extra devices
 PlanDays=30
 DefaultBudgetBytesPerSecond=12_500_000 // 100 Mbit/s per direction, shared over all nodes
)
var safeReference=regexp.MustCompile(`^[A-Za-z0-9_.:-]{1,128}$`)
func isUUID(s string)bool {u,err:=uuid.Parse(s);return err==nil&&u!=uuid.Nil&&u.String()==s}
func Price(extra int)(int64,error){
 if extra<0||extra>2{return 0,ErrInvalid}
 return PriceBaseMinor+int64(extra)*PricePerExtraMinor,nil
}

type Order struct {
 ID string `json:"id"`
 RequestID string `json:"requestId"`
 AccountID string `json:"accountId"`
 EntitlementID string `json:"entitlementId,omitempty"`
 AmountMinor int64 `json:"amountMinor"`
 Currency string `json:"currency"`
 ExtraDevices int `json:"extraDevices"`
 Status string `json:"status"`
 ExpiresAt time.Time `json:"expiresAt"`
}

// CreateOrder is called after authenticating a customer account or from a
// trusted local operator. The caller may request add-ons but never a price,
// speed, unlimited bandwidth or slot count directly.
func CreateOrder(ctx context.Context,db *sql.DB,account,request,entitlement string,extra int)(Order,error){
 out:=Order{}
 price,err:=Price(extra)
 if db==nil||!isUUID(account)||!isUUID(request)||err!=nil||
  (entitlement!=""&&!isUUID(entitlement)){return out,ErrInvalid}
 tx,err:=db.BeginTx(ctx,&sql.TxOptions{Isolation:sql.LevelReadCommitted})
 if err!=nil{return out,err}
 defer tx.Rollback()
 var enabled bool
 err=tx.QueryRowContext(ctx,`SELECT enabled FROM elx_lk_accounts WHERE id=$1 FOR UPDATE`,account).Scan(&enabled)
 if errors.Is(err,sql.ErrNoRows)||!enabled{return out,ErrConflict}
 if err!=nil{return out,err}
 if entitlement!=""{
  var owner bool
  err=tx.QueryRowContext(ctx,`SELECT EXISTS(SELECT 1 FROM elx_lk_ownership
   WHERE account_id=$1 AND entitlement_id=$2)`,account,entitlement).Scan(&owner)
  if err!=nil{return out,err}
  if !owner{return out,ErrConflict}
 }
 // An account lock above serializes idempotent retries and also throttles
 // pending checkouts without a separate vulnerable public payment endpoint.
 var pending int
 err=tx.QueryRowContext(ctx,`SELECT count(*) FROM elx_checkout_orders
  WHERE account_id=$1 AND status='pending' AND expires_at>clock_timestamp()`,account).Scan(&pending)
 if err!=nil{return out,err}
 if pending>20{return out,ErrConflict}

 var storedEnt sql.NullString
 err=tx.QueryRowContext(ctx,`SELECT id::text,request_id::text,account_id::text,
  entitlement_id::text,amount_minor,currency,addon_devices,status,expires_at
  FROM elx_checkout_orders WHERE account_id=$1 AND request_id=$2`,account,request).
  Scan(&out.ID,&out.RequestID,&out.AccountID,&storedEnt,&out.AmountMinor,
   &out.Currency,&out.ExtraDevices,&out.Status,&out.ExpiresAt)
 if err==nil{
  if storedEnt.Valid{out.EntitlementID=storedEnt.String}
  if out.EntitlementID!=entitlement||out.ExtraDevices!=extra||out.AmountMinor!=price{
   return Order{},ErrConflict
  }
  return out,tx.Commit()
 }
 if !errors.Is(err,sql.ErrNoRows){return out,err}

 out=Order{ID:uuid.NewString(),RequestID:request,AccountID:account,
  EntitlementID:entitlement,AmountMinor:price,Currency:Currency,
  ExtraDevices:extra,Status:"pending"}
 var target any
 if entitlement!=""{target=entitlement}
 err=tx.QueryRowContext(ctx,`INSERT INTO elx_checkout_orders
  (id,request_id,account_id,entitlement_id,addon_devices,amount_minor,currency,
   expires_at)
  VALUES($1,$2,$3,$4,$5,$6,'RUB',clock_timestamp()+interval '24 hours')
  RETURNING expires_at`,out.ID,request,account,target,extra,price).Scan(&out.ExpiresAt)
 if err!=nil{return Order{},err}
 return out,tx.Commit()
}

// VerifiedEvent is emitted only after the separate payment reader has
// independently verified a provider settlement. Payment reader owns private
// signing keys; Control owns only its pinned public verification key.
type VerifiedEvent struct {
 Version int `json:"version"`
 EventID string `json:"eventId"`
 OrderID string `json:"orderId"`
 Provider string `json:"provider"`
 ProviderPaymentID string `json:"providerPaymentId"`
 AmountMinor int64 `json:"amountMinor"`
 Currency string `json:"currency"`
 ConfirmedUnix int64 `json:"confirmedUnix"`
}
type SignedEvent struct {
 Event VerifiedEvent `json:"event"`
 Signature string `json:"signature"`
}
func (e VerifiedEvent) valid()bool {
 if e.Version!=1||!isUUID(e.EventID)||!isUUID(e.OrderID)||
  !safeReference.MatchString(e.Provider)||!safeReference.MatchString(e.ProviderPaymentID)||
  e.AmountMinor<PriceBaseMinor||e.AmountMinor>PriceBaseMinor+2*PricePerExtraMinor||
  e.Currency!=Currency||e.ConfirmedUnix<=0{return false}
 return true
}
func (e VerifiedEvent) transcript()[]byte {
 // Each reference is restricted to an ASCII set that excludes newline.
 return []byte(fmt.Sprintf("elx-settled-payment-v1\n%s\n%s\n%s\n%s\n%d\n%s\n%d",
  e.EventID,e.OrderID,e.Provider,e.ProviderPaymentID,
  e.AmountMinor,e.Currency,e.ConfirmedUnix))
}
func Verify(public ed25519.PublicKey,signed SignedEvent)(VerifiedEvent,error){
 if len(public)!=ed25519.PublicKeySize||!signed.Event.valid(){return VerifiedEvent{},ErrInvalid}
 raw,err:=base64.StdEncoding.DecodeString(signed.Signature)
 if err!=nil||len(raw)!=ed25519.SignatureSize||
  base64.StdEncoding.EncodeToString(raw)!=signed.Signature||
  !ed25519.Verify(public,signed.Event.transcript(),raw){
  return VerifiedEvent{},ErrUnverified
 }
 return signed.Event,nil
}

// SignForVerifier is exported so a separate payment-verifier executable can
// implement this wire contract. NEVER ship its private key to Control.
func SignForVerifier(event VerifiedEvent,private ed25519.PrivateKey)(SignedEvent,error){
 if !event.valid()||len(private)!=ed25519.PrivateKeySize{return SignedEvent{},ErrInvalid}
 return SignedEvent{Event:event,Signature:base64.StdEncoding.EncodeToString(
  ed25519.Sign(private,event.transcript()))},nil
}
type Applied struct {
 OrderID string `json:"orderId"`
 EntitlementID string `json:"entitlementId"`
 ProfileID string `json:"profileId"`
 Status string `json:"status"`
 AlreadyApplied bool `json:"alreadyApplied"`
}

// ApplyVerifiedPayment is the ONLY entitlement-granting entry point. Verify
// MUST run before this method, and the accepted event is recorded with a
// UNIQUE provider transaction. All rights, credentials and outbox writes
// commit atomically; retries cannot extend a subscription twice.
func ApplySignedPayment(ctx context.Context,db *sql.DB,signed SignedEvent,
 public ed25519.PublicKey)(Applied,error){
 e,err:=Verify(public,signed)
 if err!=nil{return Applied{},err}
 return applyVerifiedPayment(ctx,db,e)
}

// Internal only: callers must verify Ed25519 evidence before reaching here.
func applyVerifiedPayment(ctx context.Context,db *sql.DB,e VerifiedEvent)(Applied,error){
 out:=Applied{OrderID:e.OrderID}
 if db==nil||!e.valid(){return out,ErrInvalid}
 tx,err:=db.BeginTx(ctx,&sql.TxOptions{Isolation:sql.LevelReadCommitted})
 if err!=nil{return out,err}
 defer tx.Rollback()
 var account,originalEnt,status string
 var requestedEnt sql.NullString
 var addon int
 var amount int64
 var expires,issued time.Time
 err=tx.QueryRowContext(ctx,`SELECT account_id::text,entitlement_id::text,
   status,addon_devices,amount_minor,expires_at,issued_at
   FROM elx_checkout_orders WHERE id=$1 FOR UPDATE`,e.OrderID).
  Scan(&account,&requestedEnt,&status,&addon,&amount,&expires,&issued)
 if errors.Is(err,sql.ErrNoRows){return out,ErrNotFound}
 if err!=nil{return out,err}
 if requestedEnt.Valid{originalEnt=requestedEnt.String}
 var current time.Time
 if err=tx.QueryRowContext(ctx,"SELECT clock_timestamp()").Scan(&current);err!=nil{return out,err}
 confirmed:=time.Unix(e.ConfirmedUnix,0).UTC()
 // Do not credit a payment that pre-dates the order or arrived before it
 // was issued. Allow small clock skew, but never a later unrelated transfer.
 if e.AmountMinor!=amount||e.Currency!=Currency||
  confirmed.Before(issued.Add(-2*time.Minute))||
  confirmed.After(expires.Add(30*time.Minute))||
  confirmed.After(current.Add(5*time.Minute)){return out,ErrConflict}
 digest:=sha256.Sum256(e.transcript())
 if status=="paid"{
  var stored []byte
  err=tx.QueryRowContext(ctx,`SELECT payload_hash FROM elx_payment_receipts
   WHERE order_id=$1 AND event_id=$2 AND provider=$3 AND provider_payment_id=$4`,
   e.OrderID,e.EventID,e.Provider,e.ProviderPaymentID).Scan(&stored)
  if err!=nil||!strings.EqualFold(fmt.Sprintf("%x",stored),fmt.Sprintf("%x",digest[:])){
   return out,ErrConflict
  }
  err=tx.QueryRowContext(ctx,`SELECT fulfilled_entitlement::text FROM elx_checkout_orders WHERE id=$1`,
   e.OrderID).Scan(&out.EntitlementID)
  if err!=nil{return out,err}
  err=tx.QueryRowContext(ctx,`SELECT id::text FROM elx_paid_profiles WHERE entitlement_id=$1`,
   out.EntitlementID).Scan(&out.ProfileID)
  if err!=nil{return out,err}
  out.Status="paid";out.AlreadyApplied=true
  return out,tx.Commit()
 }
 if status!="pending"{return out,ErrConflict}
 // Re-using a different payment event for the same provider transaction is
 // never a second entitlement credit, even across unrelated orders.
 var used bool
 err=tx.QueryRowContext(ctx,`SELECT EXISTS(SELECT 1 FROM elx_payment_receipts
  WHERE (provider=$1 AND provider_payment_id=$2) OR event_id=$3)`,
  e.Provider,e.ProviderPaymentID,e.EventID).Scan(&used)
 if err!=nil{return out,err}
 if used{return out,ErrConflict}
 var target string
 slots:=2+addon
 if originalEnt=="" {
  target=uuid.NewString()
  if _,err=tx.ExecContext(ctx,`INSERT INTO elx_entitlements
   (id,active_slots,valid_until) VALUES($1,$2,clock_timestamp()+interval '30 days')`,
   target,slots);err!=nil{return out,err}
  if _,err=tx.ExecContext(ctx,`INSERT INTO elx_rate_budgets
   (entitlement_id,up_limit,down_limit) VALUES($1,$2,$2)`,
   target,DefaultBudgetBytesPerSecond);err!=nil{return out,err}
  if _,err=tx.ExecContext(ctx,`INSERT INTO elx_lk_ownership(entitlement_id,account_id)
   VALUES($1,$2)`,target,account);err!=nil{return out,err}
  // A profile's VLESS credential is not a subscription URL. The latter is
  // a separate bearer secret, disclosed only after provisioning succeeds.
  profile,secret,sub:=uuid.NewString(),uuid.NewString(),uuid.NewString()
  email:="elx-"+strings.ReplaceAll(profile,"-","")
  if _,err=tx.ExecContext(ctx,`INSERT INTO elx_paid_profiles
   (id,entitlement_id,vless_id,subscription_id,client_email)
   VALUES($1,$2,$3,$4,$5)`,profile,target,secret,sub,email);err!=nil{return out,err}
  job:=uuid.NewSHA1(uuid.NameSpaceURL,[]byte("elx/profile-create/"+profile))
  if _,err=tx.ExecContext(ctx,`INSERT INTO elx_profile_provision_jobs(id,profile_id)
   VALUES($1,$2)`,job,profile);err!=nil{return out,err}
  out.ProfileID=profile
 }else{
  target=originalEnt
  // Lock entitlement before any renewal and reject a plan downgrade while
  // more slots are occupied. Existing sessions are never silently released.
  var occupied int
  var enabled bool
  err=tx.QueryRowContext(ctx,`SELECT enabled FROM elx_entitlements
   WHERE id=$1 FOR UPDATE`,target).Scan(&enabled)
  if errors.Is(err,sql.ErrNoRows){return out,ErrConflict}
  if err!=nil{return out,err}
  err=tx.QueryRowContext(ctx,`SELECT count(*) FROM elx_session_owners
    WHERE entitlement_id=$1 AND state<>'released'`,target).Scan(&occupied)
  if err!=nil{return out,err}
  if occupied>slots{return out,ErrConflict}
  var owner bool
  err=tx.QueryRowContext(ctx,`SELECT EXISTS(SELECT 1 FROM elx_lk_ownership
   WHERE entitlement_id=$1 AND account_id=$2)`,target,account).Scan(&owner)
  if err!=nil{return out,err}
  if !owner{return out,ErrConflict}
  // Billing grants cannot raise or zero the purchased shared speed budget.
  var newExpiry time.Time
  if err=tx.QueryRowContext(ctx,`UPDATE elx_entitlements SET
    valid_until=GREATEST(valid_until,clock_timestamp())+interval '30 days',
    enabled=true,active_slots=$2 WHERE id=$1 RETURNING valid_until`,
    target,slots).Scan(&newExpiry);err!=nil{return out,err}
  err=tx.QueryRowContext(ctx,`SELECT id::text FROM elx_paid_profiles WHERE entitlement_id=$1`,
   target).Scan(&out.ProfileID)
  if errors.Is(err,sql.ErrNoRows){return out,ErrConflict}
  if err!=nil{return out,err}
  job:=uuid.NewSHA1(uuid.NameSpaceURL,[]byte("elx/profile-expiry/"+e.OrderID))
  if _,err=tx.ExecContext(ctx,`INSERT INTO elx_profile_expiry_jobs
   (id,order_id,profile_id,valid_until) VALUES($1,$2,$3,$4)`,
   job,e.OrderID,out.ProfileID,newExpiry);err!=nil{return out,err}
  _=enabled
 }
 if _,err=tx.ExecContext(ctx,`INSERT INTO elx_payment_receipts
  (event_id,provider,provider_payment_id,order_id,amount_minor,currency,confirmed_at,payload_hash)
  VALUES($1,$2,$3,$4,$5,'RUB',$6,$7)`,
  e.EventID,e.Provider,e.ProviderPaymentID,e.OrderID,e.AmountMinor,confirmed,digest[:]);err!=nil{
  return Applied{},err
 }
 if _,err=tx.ExecContext(ctx,`UPDATE elx_checkout_orders
  SET status='paid',fulfilled_entitlement=$2 WHERE id=$1`,e.OrderID,target);err!=nil{
  return Applied{},err
 }
 out.EntitlementID=target;out.Status="paid"
 return out,tx.Commit()
}
