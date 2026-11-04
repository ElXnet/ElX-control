package lk

import (
 "context"
 "crypto/rand"
 "crypto/sha256"
 "database/sql"
 "errors"
 "time"

 "github.com/google/uuid"
)

type Store struct { DB *sql.DB }
type Account struct {
 ID string `json:"id"`
 Email string `json:"email"`
 CSRF string `json:"csrf"`
 token string
}
func (a Account) Token() string{return a.token}

func isID(text string)bool{
 id,err:=uuid.Parse(text)
 return err==nil&&id!=uuid.Nil&&id.String()==text
}

func newSession(ctx context.Context,tx *sql.Tx,account string)(string,error){
 _,token,err:=secret()
 if err!=nil{return "",err}
 hash,_:=tokenDigest(token)
 _,err=tx.ExecContext(ctx,`INSERT INTO elx_lk_sessions(token_hash,account_id,expires_at)
  VALUES($1,$2,clock_timestamp()+interval '7 days')`,hash[:],account)
 if err!=nil{return "",err}
 return token,nil
}

// IssueInvite must ONLY be called by a trusted local operator command. The
// raw invitation is printed once and never persisted.
func (s Store) IssueInvite(ctx context.Context,entitlement string,ttl time.Duration)(string,error){
 if s.DB==nil||!isID(entitlement)||ttl<time.Hour||ttl>30*24*time.Hour{return "",ErrInvalid}
 tx,err:=s.DB.BeginTx(ctx,nil)
 if err!=nil{return "",err}
 defer tx.Rollback()
 var enabled bool
 err=tx.QueryRowContext(ctx,"SELECT enabled FROM elx_entitlements WHERE id=$1 FOR UPDATE",entitlement).Scan(&enabled)
 if errors.Is(err,sql.ErrNoRows){return "",ErrInvalid}
 if err!=nil{return "",err}
 if !enabled{return "",ErrInvalid}
 var owned bool
 if err=tx.QueryRowContext(ctx,"SELECT EXISTS(SELECT 1 FROM elx_lk_ownership WHERE entitlement_id=$1)",entitlement).Scan(&owned);err!=nil{return "",err}
 if owned{return "",ErrConflict}
 _,token,err:=secret()
 if err!=nil{return "",err}
 hash,_:=tokenDigest(token)
 _,err=tx.ExecContext(ctx,`INSERT INTO elx_lk_invites(token_hash,entitlement_id,expires_at)
  VALUES($1,$2,clock_timestamp()+($3::bigint * interval '1 second'))`,
  hash[:],entitlement,int64(ttl.Seconds()))
 if err!=nil{return "",err}
 return token,tx.Commit()
}

func inviteHash(invitation string)([32]byte,error){
 h,err:=tokenDigest(invitation)
 if err!=nil{return [32]byte{},ErrInvite}
 return h,nil
}
func lockInvite(ctx context.Context,tx *sql.Tx,invitation string)(string,[]byte,error){
 hash,err:=inviteHash(invitation)
 if err!=nil{return "",nil,err}
 var entitlement string
 err=tx.QueryRowContext(ctx,`SELECT entitlement_id::text FROM elx_lk_invites
 WHERE token_hash=$1 AND redeemed_at IS NULL AND expires_at>clock_timestamp()
 FOR UPDATE`,hash[:]).Scan(&entitlement)
 if errors.Is(err,sql.ErrNoRows){return "",nil,ErrInvite}
 return entitlement,hash[:],err
}
func availableEntitlement(ctx context.Context,tx *sql.Tx,entitlement string)error{
 var enabled bool
 var until time.Time
 err:=tx.QueryRowContext(ctx,"SELECT enabled,valid_until FROM elx_entitlements WHERE id=$1 FOR UPDATE",entitlement).Scan(&enabled,&until)
 if err!=nil{return err}
 var current time.Time
 if err=tx.QueryRowContext(ctx,"SELECT clock_timestamp()").Scan(&current);err!=nil{return err}
 if !enabled||!until.After(current){return ErrInvite}
 var count int
 if err=tx.QueryRowContext(ctx,"SELECT count(*) FROM elx_lk_ownership WHERE entitlement_id=$1",entitlement).Scan(&count);err!=nil{return err}
 if count>0{return ErrConflict}
 return nil
}
func (s Store) Register(ctx context.Context,email,password,invitation string)(Account,error){
 var out Account
 addr,err:=normalizedEmail(email)
 if s.DB==nil||err!=nil||!validPassword(password){return out,ErrInvalid}
 salt:=make([]byte,16)
 if _,err=rand.Read(salt);err!=nil{return out,err}
 hash,err:=derive(password,salt)
 if err!=nil{return out,err}
 id,err:=uuid.NewRandom()
 if err!=nil{return out,err}
 tx,err:=s.DB.BeginTx(ctx,nil)
 if err!=nil{return out,err}
 defer tx.Rollback()
 entitlement,inviteHash,err:=lockInvite(ctx,tx,invitation)
 if err!=nil{return out,err}
 if err=availableEntitlement(ctx,tx,entitlement);err!=nil{return out,err}
 var exists bool
 if err=tx.QueryRowContext(ctx,"SELECT EXISTS(SELECT 1 FROM elx_lk_accounts WHERE email=$1)",addr).Scan(&exists);err!=nil{return out,err}
 if exists{return out,ErrConflict}
 _,err=tx.ExecContext(ctx,`INSERT INTO elx_lk_accounts(id,email,password_salt,password_hash,password_iterations)
  VALUES($1,$2,$3,$4,$5)`,id,addr,salt,hash,passwordIterations)
 if err!=nil{return out,err}
 _,err=tx.ExecContext(ctx,"INSERT INTO elx_lk_ownership(entitlement_id,account_id) VALUES($1,$2)",entitlement,id)
 if err!=nil{return out,err}
 _,err=tx.ExecContext(ctx,`UPDATE elx_lk_invites SET redeemed_by=$2,redeemed_at=clock_timestamp()
  WHERE token_hash=$1 AND redeemed_at IS NULL`,inviteHash,id)
 if err!=nil{return out,err}
 token,err:=newSession(ctx,tx,id.String())
 if err!=nil{return out,err}
 if err=tx.Commit();err!=nil{return out,err}
 return Account{ID:id.String(),Email:addr,CSRF:csrfForToken(token),token:token},nil
}

func (s Store) Claim(ctx context.Context,accountID,invitation string)(string,error){
 if s.DB==nil||!isID(accountID){return "",ErrUnauthorized}
 tx,err:=s.DB.BeginTx(ctx,nil)
 if err!=nil{return "",err}
 defer tx.Rollback()
 entitlement,hash,err:=lockInvite(ctx,tx,invitation)
 if err!=nil{return "",err}
 if err=availableEntitlement(ctx,tx,entitlement);err!=nil{return "",err}
 _,err=tx.ExecContext(ctx,"INSERT INTO elx_lk_ownership(entitlement_id,account_id) VALUES($1,$2)",entitlement,accountID)
 if err!=nil{return "",err}
 _,err=tx.ExecContext(ctx,"UPDATE elx_lk_invites SET redeemed_by=$2,redeemed_at=clock_timestamp() WHERE token_hash=$1",hash,accountID)
 if err!=nil{return "",err}
 return entitlement,tx.Commit()
}

func (s Store) Authenticate(ctx context.Context,token string)(Account,error){
 var account Account
 if s.DB==nil{return account,ErrUnauthorized}
 digest,err:=tokenDigest(token)
 if err!=nil{return account,ErrUnauthorized}
 err=s.DB.QueryRowContext(ctx,`SELECT a.id::text,a.email FROM elx_lk_sessions s
 JOIN elx_lk_accounts a ON a.id=s.account_id WHERE s.token_hash=$1
 AND s.revoked_at IS NULL AND s.expires_at>clock_timestamp() AND a.enabled`,digest[:]).
 Scan(&account.ID,&account.Email)
 if errors.Is(err,sql.ErrNoRows){return Account{},ErrUnauthorized}
 if err!=nil{return Account{},err}
 account.CSRF=csrfForToken(token)
 account.token=token
 return account,nil
}
func (s Store) Logout(ctx context.Context,token string)error{
 if s.DB==nil{return ErrUnauthorized}
 hash,err:=tokenDigest(token)
 if err!=nil{return ErrUnauthorized}
 _,err=s.DB.ExecContext(ctx,`UPDATE elx_lk_sessions SET revoked_at=clock_timestamp()
 WHERE token_hash=$1 AND revoked_at IS NULL`,hash[:])
 return err
}
func (s Store) Owns(ctx context.Context,accountID,entitlement string)(bool,error){
 if s.DB==nil||!isID(accountID)||!isID(entitlement){return false,ErrUnauthorized}
 var ok bool
 err:=s.DB.QueryRowContext(ctx,`SELECT EXISTS(SELECT 1 FROM elx_lk_ownership
 WHERE account_id=$1 AND entitlement_id=$2)`,accountID,entitlement).Scan(&ok)
 return ok,err
}
func (s Store) Entitlements(ctx context.Context,accountID string)([]string,error){
 out:=[]string{}
 if s.DB==nil||!isID(accountID){return out,ErrUnauthorized}
 rows,err:=s.DB.QueryContext(ctx,`SELECT entitlement_id::text FROM elx_lk_ownership
 WHERE account_id=$1 ORDER BY entitlement_id LIMIT 101`,accountID)
 if err!=nil{return out,err}
 defer rows.Close()
 for rows.Next(){
  var id string
  if err:=rows.Scan(&id);err!=nil{return out,err}
  out=append(out,id)
 }
 if err=rows.Err();err!=nil{return out,err}
 if len(out)>100{return nil,ErrInvalid}
 return out,nil
}

// The hex token hashes are never returned to browser-facing callers.
var _ = sha256.Size
