// Package lk implements invite-only customer identities for ElX Control.
// Administrator tokens and public subscription links are not customer logins.
package lk

import (
 "crypto/hmac"
 "crypto/pbkdf2"
 "crypto/rand"
 "crypto/sha256"
 "crypto/subtle"
 "encoding/base64"
 "errors"
 "net/mail"
 "strings"
)

var (
 ErrInvalid=errors.New("invalid LK input")
 ErrUnauthorized=errors.New("invalid credentials or session")
 ErrInvite=errors.New("invalid or expired invitation")
 ErrConflict=errors.New("account or entitlement already exists")
 ErrThrottle=errors.New("too many authentication attempts")
)
const passwordIterations=600000
const minPasswordLength=12
const maxPasswordLength=128
const cookieName="__Host-elx-lk"

func normalizedEmail(raw string)(string,error) {
 email:=strings.ToLower(strings.TrimSpace(raw))
 if len(email)<3||len(email)>254||strings.ContainsAny(email," \t\r\n\x00") {return "",ErrInvalid}
 addr,err:=mail.ParseAddress(email)
 if err!=nil||addr.Address!=email{return "",ErrInvalid}
 return email,nil
}
func validPassword(value string)bool{return len(value)>=minPasswordLength&&len(value)<=maxPasswordLength}
func derive(password string,salt []byte)([]byte,error){
 if len(salt)!=16{return nil,ErrInvalid}
 return pbkdf2.Key(sha256.New,password,salt,passwordIterations,32)
}
func checkPassword(password string,salt,hash []byte)bool{
 if len(salt)!=16||len(hash)!=32{return false}
 got,err:=derive(password,salt)
 return err==nil&&subtle.ConstantTimeCompare(got,hash)==1
}
func secret()(raw []byte,encoded string,err error){
 raw=make([]byte,32)
 if _,err=rand.Read(raw);err!=nil{return nil,"",err}
 return raw,base64.RawURLEncoding.EncodeToString(raw),nil
}
func tokenDigest(value string)([32]byte,error){
 var empty [32]byte
 raw,err:=base64.RawURLEncoding.DecodeString(value)
 if err!=nil||len(raw)!=32||base64.RawURLEncoding.EncodeToString(raw)!=value{
  return empty,ErrUnauthorized
 }
 return sha256.Sum256(raw),nil
}
func csrfForToken(value string)string{
 raw,_:=base64.RawURLEncoding.DecodeString(value)
 m:=hmac.New(sha256.New,raw)
 _,_=m.Write([]byte("elx-lk-csrf-v1"))
 return base64.RawURLEncoding.EncodeToString(m.Sum(nil))
}
func validCSRF(token,header string)bool{
 if token==""||header==""{return false}
 a:=csrfForToken(token)
 return hmac.Equal([]byte(a),[]byte(header))
}
