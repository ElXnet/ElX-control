package lk

import (
 "context"
 "crypto/sha256"
 "crypto/subtle"
 "database/sql"
 "errors"
 "time"
)

// Login uses PostgreSQL-backed per-identity throttling: multiple panel
// instances share the same failure budget. A transport-level IP limiter is
// additionally required before exposing this endpoint to the public Internet.
func (s Store) Login(ctx context.Context,email,password string)(Account,error){
 var out Account
 normalized,err:=normalizedEmail(email)
 if s.DB==nil||err!=nil||len(password)==0||len(password)>maxPasswordLength{
  return out,ErrUnauthorized
 }
 tx,err:=s.DB.BeginTx(ctx,&sql.TxOptions{Isolation:sql.LevelReadCommitted})
 if err!=nil{return out,err}
 defer tx.Rollback()
 identity:=sha256.Sum256([]byte(normalized))
 _,err=tx.ExecContext(ctx,`INSERT INTO elx_lk_login_attempts(email_hash)
  VALUES($1) ON CONFLICT DO NOTHING`,identity[:])
 if err!=nil{return out,err}
 var failures int
 var window time.Time
 var blocked sql.NullTime
 err=tx.QueryRowContext(ctx,`SELECT failures,window_start,blocked_until
  FROM elx_lk_login_attempts WHERE email_hash=$1 FOR UPDATE`,identity[:]).
  Scan(&failures,&window,&blocked)
 if err!=nil{return out,err}
 var now time.Time
 if err=tx.QueryRowContext(ctx,"SELECT clock_timestamp()").Scan(&now);err!=nil{return out,err}
 if blocked.Valid && blocked.Time.After(now){return out,ErrThrottle}
 if now.Sub(window)>=10*time.Minute {failures=0;window=now}

 var accountID string
 var salt,hash []byte
 var enabled bool
 var iterations int
 err=tx.QueryRowContext(ctx,`SELECT id::text,password_salt,password_hash,password_iterations,enabled
  FROM elx_lk_accounts WHERE email=$1`,normalized).
  Scan(&accountID,&salt,&hash,&iterations,&enabled)
 if errors.Is(err,sql.ErrNoRows){
  accountID=""
  salt=make([]byte,16)
  hash=make([]byte,32)
  iterations=passwordIterations
 }else if err!=nil{return out,err}
 // Use the real stored KDF work factor, or a dummy derivation for unknown
 // accounts. Both paths require comparable computation, avoiding enumeration.
 valid:=false
 if iterations>=passwordIterations && iterations<=2000000 && len(salt)==16 && len(hash)==32{
  derived,kdfErr:=deriveWithIterations(password,salt,iterations)
  if kdfErr!=nil{return out,kdfErr}
  valid=enabled && accountID!="" && subtle.ConstantTimeCompare(derived,hash)==1
 }
 if !valid{
  failures++
  var blockedFor any
  if failures>=5 {blockedFor=now.Add(15*time.Minute)}
  _,err=tx.ExecContext(ctx,`UPDATE elx_lk_login_attempts
   SET failures=$2,window_start=$3,blocked_until=$4 WHERE email_hash=$1`,
   identity[:],failures,window,blockedFor)
  if err!=nil{return out,err}
  if err=tx.Commit();err!=nil{return out,err}
  return Account{},ErrUnauthorized
 }
 _,err=tx.ExecContext(ctx,`UPDATE elx_lk_login_attempts SET failures=0,
  window_start=clock_timestamp(),blocked_until=NULL WHERE email_hash=$1`,identity[:])
 if err!=nil{return out,err}
 token,err:=newSession(ctx,tx,accountID)
 if err!=nil{return out,err}
 if err=tx.Commit();err!=nil{return out,err}
 return Account{ID:accountID,Email:normalized,CSRF:csrfForToken(token),token:token},nil
}
