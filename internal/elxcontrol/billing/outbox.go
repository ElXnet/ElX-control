package billing

import (
 "bytes"
 "context"
 "database/sql"
 "errors"
 "fmt"
 "time"

 "github.com/ElXnet/ElX-control/internal/elxcontrol/journal"
 "github.com/ElXnet/ElX-control/internal/elxcontrol/policytransport"
 "github.com/google/uuid"
)

type ProvisionJob struct {
 JobID string `json:"jobId"`
 ClaimID string `json:"claimId"`
 Operation string `json:"operation"`
 ProfileID string `json:"profileId"`
 EntitlementID string `json:"entitlementId"`
 VLESSID string `json:"vlessId"`
 SubscriptionID string `json:"subscriptionId"`
 ClientEmail string `json:"clientEmail"`
 ValidUntil time.Time `json:"validUntil"`
}

// ClaimNext hands the panel one idempotent operation. An expired lease can be
// retried by a second panel process; all attributes (including credentials)
// remain unchanged. Only a unix-socket trusted panel process sees this data.
func ClaimNext(ctx context.Context,db *sql.DB)(ProvisionJob,error){
 var out ProvisionJob
 if db==nil{return out,ErrInvalid}
 tx,err:=db.BeginTx(ctx,&sql.TxOptions{Isolation:sql.LevelReadCommitted})
 if err!=nil{return out,err}
 defer tx.Rollback()
 var storedStatus string
 err=tx.QueryRowContext(ctx,`SELECT j.id::text,j.status,p.id::text,
   p.entitlement_id::text,p.vless_id::text,p.subscription_id,p.client_email,
   e.valid_until
   FROM elx_profile_provision_jobs j
   JOIN elx_paid_profiles p ON p.id=j.profile_id
   JOIN elx_entitlements e ON e.id=p.entitlement_id
   WHERE (j.status IN ('pending','enable_pending') OR
     (j.status IN ('leased','enable_leased') AND j.lease_until<clock_timestamp()))
     AND e.enabled AND e.valid_until>clock_timestamp()
   ORDER BY j.created_at,j.id LIMIT 1 FOR UPDATE OF j SKIP LOCKED`).
  Scan(&out.JobID,&storedStatus,&out.ProfileID,&out.EntitlementID,
   &out.VLESSID,&out.SubscriptionID,&out.ClientEmail,&out.ValidUntil)
 if errors.Is(err,sql.ErrNoRows){return out,ErrNotFound}
 if err!=nil{return out,err}
 next:="leased"
 out.Operation="create-disabled"
 if storedStatus=="enable_pending"||storedStatus=="enable_leased"{
  next="enable_leased";out.Operation="enable"
 }
 out.ClaimID=uuid.NewString()
 _,err=tx.ExecContext(ctx,`UPDATE elx_profile_provision_jobs
   SET status=$2,lease_owner=$3,lease_until=clock_timestamp()+interval '3 minutes',
   attempts=attempts+1 WHERE id=$1`,out.JobID,next,out.ClaimID)
 if err!=nil{return ProvisionJob{},err}
 return out,tx.Commit()
}

func ConfirmJob(ctx context.Context,db *sql.DB,job,claim,operation string)(string,error){
 if db==nil||!isUUID(job)||!isUUID(claim) ||
  (operation!="create-disabled"&&operation!="enable"){return "",ErrInvalid}
 tx,err:=db.BeginTx(ctx,&sql.TxOptions{Isolation:sql.LevelReadCommitted})
 if err!=nil{return "",err}
 defer tx.Rollback()
 var status string
 var profile string
 var owner sql.NullString
 var until sql.NullTime
 err=tx.QueryRowContext(ctx,`SELECT status,profile_id::text,lease_owner::text,lease_until
  FROM elx_profile_provision_jobs WHERE id=$1 FOR UPDATE`,job).
  Scan(&status,&profile,&owner,&until)
 if errors.Is(err,sql.ErrNoRows){return "",ErrNotFound}
 if err!=nil{return "",err}
 if !owner.Valid||owner.String!=claim||!until.Valid||!until.Time.After(time.Now()) {
  return "",ErrConflict
 }
 desiredStatus,profileStatus:="leased","staged"
 nextJob:="staged"
 if operation=="enable" {
  desiredStatus="enable_leased";profileStatus="active";nextJob="active"
 }
 if status!=desiredStatus{return "",ErrConflict}
 if operation=="enable" {
  // A rotation can begin after this worker claims its task. Never accept
  // a stale success ACK while the old incarnation is being drained.
  var rotating bool
  err=tx.QueryRowContext(ctx,`SELECT EXISTS(
    SELECT 1 FROM elx_paid_profiles p
    JOIN elx_rate_grants g ON g.entitlement_id=p.entitlement_id
    JOIN elx_core_rotations r ON r.node_id=g.node_id
    WHERE p.id=$1 AND r.state='quiescing')`,profile).Scan(&rotating)
  if err!=nil{return "",err}
  if rotating{return "",ErrConflict}
 }
 _,err=tx.ExecContext(ctx,`UPDATE elx_paid_profiles SET status=$2 WHERE id=$1`,
  profile,profileStatus)
 if err!=nil{return "",err}
 _,err=tx.ExecContext(ctx,`UPDATE elx_profile_provision_jobs
  SET status=$2,lease_owner=NULL,lease_until=NULL,completed_at=clock_timestamp()
  WHERE id=$1`,job,nextJob)
 if err!=nil{return "",err}
 return nextJob,tx.Commit()
}

// QueueReadyEnables automatically moves profiles created disabled by the
// panel into enable-ready state only after Control can prove that their
// subscription matches applied policy targets, purchased rate budgets and
// the current trusted ElXray identity. This does NOT override Xray leases.
func QueueReadyEnables(ctx context.Context,db *sql.DB,bindings []policytransport.Binding)(int,error){
 if db==nil||len(bindings)==0||len(bindings)>10000{return 0,ErrInvalid}
 if err:=policytransport.ValidateBindings(bindings);err!=nil{return 0,ErrInvalid}
 // The individual profile status acts as the lock boundary for concurrent
 // workers; no optimistic enablement occurs on errors or absent grants.
 rows,err:=db.QueryContext(ctx,`SELECT p.id::text FROM elx_paid_profiles p
  JOIN elx_profile_provision_jobs j ON j.profile_id=p.id
  WHERE p.status='staged' AND j.status='staged'
  ORDER BY p.id LIMIT 100`)
 if err!=nil{return 0,err}
 var profiles []string
 for rows.Next(){var id string;if err:=rows.Scan(&id);err!=nil{rows.Close();return 0,err};profiles=append(profiles,id)}
 err=rows.Err();rows.Close()
 if err!=nil{return 0,err}
 var queued int
 for _,id:=range profiles{
  ready,err:=readyToEnable(ctx,db,id,bindings)
  if err!=nil{return queued,err}
  if !ready{continue}
  // Another process might have queued it already; CAS avoids duplicates.
  res,err:=db.ExecContext(ctx,`UPDATE elx_profile_provision_jobs
   SET status='enable_pending',completed_at=NULL
   WHERE profile_id=$1 AND status='staged'
   AND EXISTS(SELECT 1 FROM elx_paid_profiles
     WHERE id=$1 AND status='staged')`,id)
  if err!=nil{return queued,err}
  n,_:=res.RowsAffected()
  queued+=int(n)
 }
 return queued,nil
}

func readyToEnable(ctx context.Context,db *sql.DB,profileID string,
 bindings []policytransport.Binding)(bool,error){
 var entitlement,subscription string
 var until time.Time
 err:=db.QueryRowContext(ctx,`SELECT p.entitlement_id::text,p.subscription_id,e.valid_until
  FROM elx_paid_profiles p JOIN elx_entitlements e ON e.id=p.entitlement_id
  WHERE p.id=$1 AND p.status='staged' AND e.enabled`,profileID).
  Scan(&entitlement,&subscription,&until)
 if errors.Is(err,sql.ErrNoRows){return false,nil}
 if err!=nil{return false,err}
 if !until.After(time.Now()){return false,nil}
 var limitUp,limitDown int64
 err=db.QueryRowContext(ctx,`SELECT up_limit,down_limit
  FROM elx_rate_budgets WHERE entitlement_id=$1`,entitlement).
  Scan(&limitUp,&limitDown)
 if err!=nil{return false,err}
 if limitUp<=0||limitDown<=0{return false,nil}
 rows,err:=db.QueryContext(ctx,`SELECT node_id::text,resource_id::text,epoch,barrier_public_key,
  committed_up,committed_down FROM elx_rate_grants WHERE entitlement_id=$1
  ORDER BY node_id,resource_id LIMIT 1001`,entitlement)
 if err!=nil{return false,err}
 type grant struct {node,resource string;epoch,up,down int64;key []byte}
 var grants []grant
 for rows.Next(){
  var g grant
  if err:=rows.Scan(&g.node,&g.resource,&g.epoch,&g.key,&g.up,&g.down);err!=nil{rows.Close();return false,err}
  grants=append(grants,g)
 }
 err=rows.Err();rows.Close()
 if err!=nil{return false,err}
 if len(grants)==0||len(grants)>1000{return false,nil}
 manifest:=make(map[journal.Target]policytransport.Binding,len(bindings))
 for _,b:=range bindings{manifest[b.Target]=b}
 var sumUp,sumDown int64
 for _,g:=range grants{
  var rotating bool
  if err=db.QueryRowContext(ctx,`SELECT EXISTS(
    SELECT 1 FROM elx_core_rotations WHERE node_id=$1
    AND state='quiescing')`,g.node).Scan(&rotating);err!=nil{
   return false,err
  }
  if rotating{return false,nil}
  if g.up<=0||g.down<=0||g.up>limitUp-sumUp||g.down>limitDown-sumDown{
   return false,nil
  }
  sumUp+=g.up;sumDown+=g.down
  b,ok:=manifest[journal.Target{NodeID:g.node,ResourceID:g.resource}]
  if !ok||b.Subscription!=subscription||b.Epoch!=g.epoch||
   !bytes.Equal(b.PublicKey,g.key){return false,nil}
  var cores int
  err=db.QueryRowContext(ctx,`SELECT count(*) FROM elx_core_identities
    WHERE node_id=$1 AND public_key=$2 AND revoked=false`,g.node,g.key).Scan(&cores)
  if err!=nil{return false,err}
  if cores!=1{return false,nil}
  // An applied policy readback is essential: DB allocation alone does not
  // prove that the subscription exists in the live VPN core.
  var applied bool
  err=db.QueryRowContext(ctx,`SELECT
   EXISTS(SELECT 1 FROM elx_operations
    WHERE node_id=$1 AND resource_id=$2 AND applied_at IS NOT NULL)
   AND NOT EXISTS(SELECT 1 FROM elx_operations
    WHERE node_id=$1 AND resource_id=$2 AND applied_at IS NULL)
   AND NOT EXISTS(SELECT 1 FROM elx_rate_moves
    WHERE node_id=$1 AND resource_id=$2 AND NOT finalized)`,
    g.node,g.resource).Scan(&applied)
  if err!=nil{return false,err}
  if !applied{return false,nil}
  ready,err:=journal.SignedFUPLeaseReady(ctx,db,entitlement,g.node,g.resource,subscription)
  if err!=nil{return false,err}
  if !ready{return false,nil}
 }
 return true,nil
}

func debugJob(j ProvisionJob)string {
 return fmt.Sprintf("%s/%s",j.JobID,j.Operation)
}

// ClaimExpiryRefresh refreshes the panel's local expires-at metadata after a
// successful Control renewal. A profile remains disabled/active as it was:
// this operation cannot bypass Control's signed core and rate policy gates.
func ClaimExpiryRefresh(ctx context.Context,db *sql.DB)(ProvisionJob,error){
 var out ProvisionJob
 if db==nil{return out,ErrInvalid}
 tx,err:=db.BeginTx(ctx,&sql.TxOptions{Isolation:sql.LevelReadCommitted})
 if err!=nil{return out,err}
 defer tx.Rollback()
 err=tx.QueryRowContext(ctx,`SELECT j.id::text,p.id::text,p.entitlement_id::text,
   p.vless_id::text,p.subscription_id,p.client_email,j.valid_until
   FROM elx_profile_expiry_jobs j
   JOIN elx_paid_profiles p ON p.id=j.profile_id
   JOIN elx_entitlements e ON e.id=p.entitlement_id
   WHERE (j.status='pending' OR (j.status='leased' AND
     j.lease_until<clock_timestamp()))
     AND p.status IN ('staged','active')
     AND e.enabled AND e.valid_until>clock_timestamp()
   ORDER BY j.valid_until DESC,j.id LIMIT 1 FOR UPDATE OF j SKIP LOCKED`).
  Scan(&out.JobID,&out.ProfileID,&out.EntitlementID,&out.VLESSID,
   &out.SubscriptionID,&out.ClientEmail,&out.ValidUntil)
 if errors.Is(err,sql.ErrNoRows){return out,ErrNotFound}
 if err!=nil{return out,err}
 out.Operation="renew-expiry"
 out.ClaimID=uuid.NewString()
 if _,err=tx.ExecContext(ctx,`UPDATE elx_profile_expiry_jobs
  SET status='leased',lease_owner=$2,
    lease_until=clock_timestamp()+interval '3 minutes',
    attempts=attempts+1 WHERE id=$1`,out.JobID,out.ClaimID);err!=nil{
  return ProvisionJob{},err
 }
 return out,tx.Commit()
}

func ConfirmExpiryRefresh(ctx context.Context,db *sql.DB,job,claim string)error{
 if db==nil||!isUUID(job)||!isUUID(claim){return ErrInvalid}
 tx,err:=db.BeginTx(ctx,&sql.TxOptions{Isolation:sql.LevelReadCommitted})
 if err!=nil{return err}
 defer tx.Rollback()
 var state string
 var owner sql.NullString
 var valid bool
 err=tx.QueryRowContext(ctx,`SELECT status,lease_owner::text,
  lease_until>clock_timestamp() FROM elx_profile_expiry_jobs
  WHERE id=$1 FOR UPDATE`,job).Scan(&state,&owner,&valid)
 if errors.Is(err,sql.ErrNoRows){return ErrNotFound}
 if err!=nil{return err}
 if state!="leased"||!owner.Valid||owner.String!=claim||!valid{return ErrConflict}
 if _,err=tx.ExecContext(ctx,`UPDATE elx_profile_expiry_jobs
  SET status='done',lease_owner=NULL,lease_until=NULL,
    completed_at=clock_timestamp() WHERE id=$1`,job);err!=nil{return err}
 return tx.Commit()
}
