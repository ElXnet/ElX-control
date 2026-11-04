package lk

import (
 "encoding/json"
 "errors"
 "io"
 "net/http"
 "strings"
 "time"

 "github.com/ElXnet/ElX-control/internal/elxcontrol/journal"
 "github.com/ElXnet/ElX-control/internal/elxcontrol/management"
 "github.com/ElXnet/ElX-control/internal/elxcontrol/session"
)
type ErrorResponse struct{Error string `json:"error"`}
func reply(w http.ResponseWriter,status int,obj any){
 w.Header().Set("Content-Type","application/json; charset=utf-8")
 w.Header().Set("Cache-Control","no-store")
 w.WriteHeader(status)
 _=json.NewEncoder(w).Encode(obj)
}
func failure(w http.ResponseWriter,err error){
 code:=http.StatusServiceUnavailable
 switch {
 case errors.Is(err,ErrInvalid),errors.Is(err,ErrInvite),errors.Is(err,journal.ErrInvalid),errors.Is(err,management.ErrSchedule):
  code=http.StatusBadRequest
 case errors.Is(err,ErrUnauthorized):code=http.StatusUnauthorized
 case errors.Is(err,ErrThrottle):code=http.StatusTooManyRequests
 case errors.Is(err,ErrConflict),errors.Is(err,journal.ErrConflict),errors.Is(err,session.ErrDrain):
  code=http.StatusConflict
 case errors.Is(err,management.ErrNotFound):code=http.StatusNotFound
 }
 reply(w,code,ErrorResponse{Error:http.StatusText(code)})
}
func readJSON(w http.ResponseWriter,r *http.Request,out any)bool{
 if !strings.HasPrefix(r.Header.Get("Content-Type"),"application/json"){
  reply(w,http.StatusUnsupportedMediaType,ErrorResponse{"Content-Type must be application/json"})
  return false
 }
 r.Body=http.MaxBytesReader(w,r.Body,4096)
 dec:=json.NewDecoder(r.Body)
 dec.DisallowUnknownFields()
 if dec.Decode(out)!=nil{failure(w,ErrInvalid);return false}
 var extra any
 if err:=dec.Decode(&extra);!errors.Is(err,io.EOF){failure(w,ErrInvalid);return false}
 return true
}
func setSession(w http.ResponseWriter,token string){
 http.SetCookie(w,&http.Cookie{
  Name:cookieName,Value:token,Path:"/",Secure:true,HttpOnly:true,
  SameSite:http.SameSiteStrictMode,MaxAge:int((7*24*time.Hour)/time.Second),
 })
}
func clearSession(w http.ResponseWriter){
 http.SetCookie(w,&http.Cookie{Name:cookieName,Value:"",Path:"/",Secure:true,HttpOnly:true,
  SameSite:http.SameSiteStrictMode,MaxAge:-1})
}
func tokenFromRequest(r *http.Request)string{
 cookie,err:=r.Cookie(cookieName)
 if err!=nil{return ""}
 return cookie.Value
}
func (s Store) requireAccount(w http.ResponseWriter,r *http.Request,write bool)(Account,bool){
 token:=tokenFromRequest(r)
 account,err:=s.Authenticate(r.Context(),token)
 if err!=nil{failure(w,err);return Account{},false}
 if write && !validCSRF(token,r.Header.Get("X-ElX-CSRF")){
  failure(w,ErrUnauthorized)
  return Account{},false
 }
 return account,true
}
func (s Store) requireOwnership(w http.ResponseWriter,r *http.Request,account Account,entitlement string)bool{
 if !isID(entitlement){failure(w,ErrInvalid);return false}
 owns,err:=s.Owns(r.Context(),account.ID,entitlement)
 if err!=nil{failure(w,err);return false}
 if !owns{failure(w,ErrUnauthorized);return false}
 return true
}

// Handler exposes only customer paths. All management/admin operations live on
// different routes and cannot be reached by a customer cookie.
func Handler(s Store)http.Handler{
 mux:=http.NewServeMux()
 mux.HandleFunc("POST /lk/v1/register",func(w http.ResponseWriter,r *http.Request){
  var v struct{Email string `json:"email"`;Password string `json:"password"`;Invite string `json:"invite"`}
  if !readJSON(w,r,&v){return}
  account,err:=s.Register(r.Context(),v.Email,v.Password,v.Invite)
  if err!=nil{failure(w,err);return}
  setSession(w,account.Token())
  reply(w,http.StatusCreated,account)
 })
 mux.HandleFunc("POST /lk/v1/login",func(w http.ResponseWriter,r *http.Request){
  var v struct{Email string `json:"email"`;Password string `json:"password"`}
  if !readJSON(w,r,&v){return}
  account,err:=s.Login(r.Context(),v.Email,v.Password)
  if err!=nil{failure(w,err);return}
  setSession(w,account.Token())
  reply(w,http.StatusOK,account)
 })
 mux.HandleFunc("GET /lk/v1/me",func(w http.ResponseWriter,r *http.Request){
  account,ok:=s.requireAccount(w,r,false)
  if !ok{return}
  reply(w,http.StatusOK,account)
 })
 mux.HandleFunc("POST /lk/v1/logout",func(w http.ResponseWriter,r *http.Request){
  account,ok:=s.requireAccount(w,r,true)
  if !ok{return}
  _=account
  if err:=s.Logout(r.Context(),tokenFromRequest(r));err!=nil{failure(w,err);return}
  clearSession(w)
  reply(w,http.StatusOK,map[string]bool{"loggedOut":true})
 })
 mux.HandleFunc("POST /lk/v1/claim",func(w http.ResponseWriter,r *http.Request){
  account,ok:=s.requireAccount(w,r,true)
  if !ok{return}
  var v struct{Invite string `json:"invite"`}
  if !readJSON(w,r,&v){return}
  entitlement,err:=s.Claim(r.Context(),account.ID,v.Invite)
  if err!=nil{failure(w,err);return}
  reply(w,http.StatusCreated,map[string]string{"entitlementId":entitlement})
 })
 mux.HandleFunc("GET /lk/v1/entitlements",func(w http.ResponseWriter,r *http.Request){
  account,ok:=s.requireAccount(w,r,false)
  if !ok{return}
  items,err:=s.Entitlements(r.Context(),account.ID)
  if err!=nil{failure(w,err);return}
  reply(w,http.StatusOK,map[string]any{"items":items})
 })
 mux.HandleFunc("GET /lk/v1/entitlements/{id}",func(w http.ResponseWriter,r *http.Request){
  account,ok:=s.requireAccount(w,r,false)
  if !ok{return}
  id:=r.PathValue("id")
  if !s.requireOwnership(w,r,account,id){return}
  details,err:=(management.SQLStore{DB:s.DB}).Get(r.Context(),id)
  if err!=nil{failure(w,err);return}
  reply(w,http.StatusOK,details)
 })
 mux.HandleFunc("POST /lk/v1/entitlements/{id}/sessions/{owner}/drain",func(w http.ResponseWriter,r *http.Request){
  account,ok:=s.requireAccount(w,r,true)
  if !ok{return}
  id,owner:=r.PathValue("id"),r.PathValue("owner")
  if !isID(owner){failure(w,ErrInvalid);return}
  if !s.requireOwnership(w,r,account,id){return}
  if err:=(management.SQLStore{DB:s.DB}).QueueDrain(r.Context(),id,owner);err!=nil{failure(w,err);return}
  reply(w,http.StatusAccepted,map[string]string{"state":"draining","release":"pending-signed-core-fence"})
 })
 mux.HandleFunc("POST /lk/v1/entitlements/{id}/devices/{device}/revoke",func(w http.ResponseWriter,r *http.Request){
  account,ok:=s.requireAccount(w,r,true)
  if !ok{return}
  id,device:=r.PathValue("id"),r.PathValue("device")
  if !isID(device){failure(w,ErrInvalid);return}
  if !s.requireOwnership(w,r,account,id){return}
  result,err:=(management.SQLStore{DB:s.DB}).RevokeDevice(r.Context(),id,device)
  if err!=nil{failure(w,err);return}
  reply(w,http.StatusAccepted,result)
 })
 return http.HandlerFunc(func(w http.ResponseWriter,r *http.Request){
  w.Header().Set("Cache-Control","no-store")
  if strings.HasPrefix(r.URL.Path,"/lk/v1/"){mux.ServeHTTP(w,r);return}
  failure(w,ErrInvalid)
 })
}
