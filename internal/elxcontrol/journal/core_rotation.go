package journal

import (
 "bytes"
 "context"
 "crypto/ed25519"
 "database/sql"
 "errors"
 "fmt"
 "time"

 "github.com/google/uuid"
)

var (
 ErrRotation=errors.New("core rotation blocked by sessions, rate barriers or signed accounting")
 ErrRotationConflict=errors.New("core rotation conflicts with pinned identity")
)
type CoreRotation struct {
 ID string `json:"id"`
 NodeID string `json:"nodeId"`
 OldIncarnation string `json:"oldIncarnation"`
 NewIncarnation string `json:"newIncarnation"`
 State string `json:"state"`
 StartedAt time.Time `json:"startedAt"`
 EarliestCutover time.Time `json:"earliestCutover"`
 AlreadyExisted bool `json:"alreadyExisted"`
}

// BeginCoreRotation revokes NEW leasing and session admissions at the node.
// Old sessions remain occupied until a signed, generation-scoped core fence
// is verified. Old unexpired 15-second leases are allowed a 45-second grace.
func BeginCoreRotation(ctx context.Context,db *sql.DB,id,node,oldBoot,newBoot string,
 newKey ed25519.PublicKey)(CoreRotation,error){
 out:=CoreRotation{}
 if db==nil||len(newKey)!=ed25519.PublicKeySize{return out,ErrInvalid}
 for _,v:=range []string{id,node,oldBoot,newBoot}{
  u,err:=uuid.Parse(v);if err!=nil||u==uuid.Nil||u.String()!=v{return out,ErrInvalid}
 }
 if oldBoot==newBoot{return out,ErrInvalid}
 tx,err:=db.BeginTx(ctx,&sql.TxOptions{Isolation:sql.LevelReadCommitted})
 if err!=nil{return out,err}
 defer tx.Rollback()
 // Serialize rotation with rate / device admission via a node-local lock.
 var priorID,priorNode,priorOld,priorNew,state string
 var priorKey []byte
 var started,cutover time.Time
 err=tx.QueryRowContext(ctx,`SELECT id::text,node_id::text,
  old_incarnation::text,new_incarnation::text,new_public_key,state,
  started_at,earliest_cutover FROM elx_core_rotations WHERE id=$1 FOR UPDATE`,
  id).Scan(&priorID,&priorNode,&priorOld,&priorNew,&priorKey,&state,&started,&cutover)
 if err==nil{
  if priorNode!=node||priorOld!=oldBoot||priorNew!=newBoot||
   !bytes.Equal(priorKey,newKey){return out,ErrRotationConflict}
  out=CoreRotation{ID:id,NodeID:node,OldIncarnation:oldBoot,
   NewIncarnation:newBoot,State:state,StartedAt:started,
   EarliestCutover:cutover,AlreadyExisted:true}
  return out,tx.Commit()
 }
 if !errors.Is(err,sql.ErrNoRows){return out,err}
 var pinned []byte
 var revoked bool
 err=tx.QueryRowContext(ctx,`SELECT public_key,revoked FROM elx_core_identities
  WHERE node_id=$1 AND incarnation=$2 FOR UPDATE`,node,oldBoot).
  Scan(&pinned,&revoked)
 if errors.Is(err,sql.ErrNoRows){return out,ErrRotationConflict}
 if err!=nil{return out,err}
 if revoked||len(pinned)!=ed25519.PublicKeySize||bytes.Equal(pinned,newKey){
  return out,ErrRotationConflict
 }
 var live int
 err=tx.QueryRowContext(ctx,`SELECT count(*) FROM elx_core_identities
  WHERE node_id=$1 AND revoked=false`,node).Scan(&live)
 if err!=nil{return out,err}
 if live!=1{return out,ErrRotationConflict}
 var hasNew bool
 err=tx.QueryRowContext(ctx,`SELECT EXISTS(SELECT 1 FROM elx_core_identities
   WHERE node_id=$1 AND incarnation=$2)`,node,newBoot).Scan(&hasNew)
 if err!=nil{return out,err}
 if hasNew{return out,ErrRotationConflict}
 err=tx.QueryRowContext(ctx,`INSERT INTO elx_core_rotations
  (id,node_id,old_incarnation,new_incarnation,new_public_key,earliest_cutover)
  VALUES($1,$2,$3,$4,$5,clock_timestamp()+interval '45 seconds')
  RETURNING state,started_at,earliest_cutover`,
  id,node,oldBoot,newBoot,[]byte(newKey)).
  Scan(&out.State,&out.StartedAt,&out.EarliestCutover)
 if err!=nil{return out,err}
 out.ID=id;out.NodeID=node;out.OldIncarnation=oldBoot;out.NewIncarnation=newBoot
 return out,tx.Commit()
}

// CompleteCoreRotation is deliberately a separate operator operation.
// Before it can switch the pinned identity, every old per-resource rate grant
// must be 0 with a *verified Ed25519* deny+drain barrier issued AFTER Begin,
// no device session may occupy the retiring node, and every enabled FUP
// schedule must have a final signed usage sample taken AFTER its barrier.
// Old stream rows remain in PostgreSQL for audit, but become inactive and
// closed; new streams are unprimed and must be explicitly enrolled.
func CompleteCoreRotation(ctx context.Context,db *sql.DB,id string)(CoreRotation,error){
 out:=CoreRotation{}
 parsed,err:=uuid.Parse(id)
 if db==nil||err!=nil||parsed==uuid.Nil||parsed.String()!=id{return out,ErrInvalid}
 tx,err:=db.BeginTx(ctx,&sql.TxOptions{Isolation:sql.LevelReadCommitted})
 if err!=nil{return out,err}
 defer tx.Rollback()
 var newKey []byte
 err=tx.QueryRowContext(ctx,`SELECT id::text,node_id::text,
  old_incarnation::text,new_incarnation::text,new_public_key,state,
  started_at,earliest_cutover FROM elx_core_rotations WHERE id=$1 FOR UPDATE`,
  id).Scan(&out.ID,&out.NodeID,&out.OldIncarnation,&out.NewIncarnation,
   &newKey,&out.State,&out.StartedAt,&out.EarliestCutover)
 if errors.Is(err,sql.ErrNoRows){return out,ErrRotationConflict}
 if err!=nil{return out,err}
 if out.State=="completed"{out.AlreadyExisted=true;return out,tx.Commit()}
 if out.State!="quiescing"{return out,ErrRotationConflict}
 var now time.Time
 if err=tx.QueryRowContext(ctx,"SELECT clock_timestamp()").Scan(&now);err!=nil{return out,err}
 if now.Before(out.EarliestCutover){return out,ErrRotation}
 var oldKey []byte
 var revoked bool
 err=tx.QueryRowContext(ctx,`SELECT public_key,revoked FROM elx_core_identities
  WHERE node_id=$1 AND incarnation=$2 FOR UPDATE`,out.NodeID,out.OldIncarnation).
  Scan(&oldKey,&revoked)
 if err!=nil{return out,err}
 if revoked||len(oldKey)!=ed25519.PublicKeySize||bytes.Equal(oldKey,newKey){
  return out,ErrRotationConflict
 }
 var owners int
 err=tx.QueryRowContext(ctx,`SELECT count(*) FROM elx_session_owners
  WHERE node_id=$1 AND state<>'released'`,out.NodeID).Scan(&owners)
 if err!=nil{return out,err}
 if owners>0{return out,ErrRotation}

 rows,err:=tx.QueryContext(ctx,`SELECT resource_id::text,entitlement_id::text,
  committed_up,committed_down,epoch,barrier_public_key
  FROM elx_rate_grants WHERE node_id=$1 ORDER BY resource_id FOR UPDATE`,out.NodeID)
 if err!=nil{return out,err}
 type grant struct {
  resource,ent string
  up,down,epoch int64
  pub []byte
 }
 var grants []grant
 for rows.Next(){var g grant;if err:=rows.Scan(&g.resource,&g.ent,&g.up,&g.down,&g.epoch,&g.pub);err!=nil{rows.Close();return out,err};grants=append(grants,g)}
 err=rows.Err();rows.Close()
 if err!=nil{return out,err}
 for _,g:=range grants {
  if g.up!=0||g.down!=0||!bytes.Equal(g.pub,oldKey){return out,ErrRotation}
  var op string
  var revision int64
  var barrier []byte
  var stamped time.Time
  err=tx.QueryRowContext(ctx,`SELECT m.operation_id::text,o.revision,
   m.barrier_signature,m.barrier_at FROM elx_rate_moves m
   JOIN elx_operations o ON o.node_id=m.node_id AND o.resource_id=m.resource_id
    AND o.operation_id=m.operation_id
   WHERE m.node_id=$1 AND m.resource_id=$2 AND m.finalized
    AND m.desired_up=0 AND m.desired_down=0
    AND o.applied_at>=$3 AND m.barrier_at>=$3
   ORDER BY m.barrier_at DESC LIMIT 1`,
   out.NodeID,g.resource,out.StartedAt).Scan(&op,&revision,&barrier,&stamped)
  if errors.Is(err,sql.ErrNoRows){return out,ErrRotation}
  if err!=nil{return out,err}
  target:=Target{NodeID:out.NodeID,ResourceID:g.resource}
  signed:=rateBarrierMessage(g.ent,target,op,g.epoch,revision,Rate{Up:0,Down:0})
  if !ed25519.Verify(ed25519.PublicKey(oldKey),signed,barrier){
   return out,ErrRotation
  }
  var pending int
  err=tx.QueryRowContext(ctx,`SELECT count(*) FROM elx_rate_moves WHERE
   node_id=$1 AND resource_id=$2 AND NOT finalized`,out.NodeID,g.resource).Scan(&pending)
  if err!=nil{return out,err}
  if pending>0{return out,ErrRotation}
  // Once a real signed core deny+drain was applied, all bytes must be
  // reported to FUP for *every* enabled schedule before we seal the boot.
  var schedules,covered int
  err=tx.QueryRowContext(ctx,`SELECT count(*) FROM elx_period_schedules sc
    JOIN elx_usage_periods p ON p.id=sc.current_period_id
    WHERE sc.entitlement_id=$1 AND sc.enabled
     AND p.starts_at<=clock_timestamp() AND p.ends_at>clock_timestamp()`,g.ent).
   Scan(&schedules)
  if err!=nil{return out,err}
  err=tx.QueryRowContext(ctx,`SELECT count(*) FROM elx_accounting_assignments a
    JOIN elx_accounting_streams st ON st.node_id=a.node_id
      AND st.executor_id=a.executor_id AND st.incarnation=a.incarnation
      AND st.accounting_id=a.accounting_id AND st.generation=a.generation
      AND st.period_id=a.period_id
    JOIN elx_period_schedules sc ON sc.current_period_id=a.period_id
    WHERE a.node_id=$1 AND a.resource_id=$2 AND a.incarnation=$3
      AND a.active AND st.primed AND NOT st.closed
      AND sc.entitlement_id=$4 AND sc.enabled
      AND st.last_received_at>=$5`,
    out.NodeID,g.resource,out.OldIncarnation,g.ent,stamped).Scan(&covered)
  if err!=nil{return out,err}
  if covered!=schedules{return out,ErrRotation}
 }
 // Discard the retiring core's allocator-pressure high-watermarks only
 // AFTER all rate grants have been cryptographically fenced, every session
 // released and final signed usage accounted. New incarnations must produce
 // freshly pinned samples; old bytes cannot be mistaken for a new core's
 // initial demand.
 _,err=tx.ExecContext(ctx,`DELETE FROM elx_rate_pressure_samples
  WHERE node_id=$1 AND incarnation=$2`,out.NodeID,out.OldIncarnation)
 if err!=nil{return out,err}
 // Accepted leases from the retiring core are invalid after takeover.
 // Delete them in the same fully fenced rotation transaction.
 _,err=tx.ExecContext(ctx,`DELETE FROM elx_rate_lease_acceptances
  WHERE node_id=$1 AND incarnation=$2`,out.NodeID,out.OldIncarnation)
 if err!=nil{return out,err}
 // Archive signed accounting WITHOUT resetting periods or watermarks.
 // Sources from the retired incarnation can never be polled again.
 _,err=tx.ExecContext(ctx,`UPDATE elx_accounting_streams SET closed=true
  WHERE node_id=$1 AND incarnation=$2 AND NOT closed`,out.NodeID,out.OldIncarnation)
 if err!=nil{return out,err}
 _,err=tx.ExecContext(ctx,`UPDATE elx_accounting_assignments SET active=false
  WHERE node_id=$1 AND incarnation=$2 AND active`,out.NodeID,out.OldIncarnation)
 if err!=nil{return out,err}
 _,err=tx.ExecContext(ctx,`UPDATE elx_core_identities SET revoked=true
  WHERE node_id=$1 AND incarnation=$2`,out.NodeID,out.OldIncarnation)
 if err!=nil{return out,err}
 _,err=tx.ExecContext(ctx,`INSERT INTO elx_core_identities(node_id,incarnation,public_key)
  VALUES($1,$2,$3)`,out.NodeID,out.NewIncarnation,newKey)
 if err!=nil{return out,err}
 _,err=tx.ExecContext(ctx,`UPDATE elx_rate_grants SET epoch=epoch+1,
  barrier_public_key=$2 WHERE node_id=$1`,out.NodeID,newKey)
 if err!=nil{return out,err}
 // An operator-enrolled paid node must follow the same pinned incarnation
 // as its live rate grants. Leaving this at the retired boot can cause a
 // future billing worker to publish an obsolete core identity.
 _,err=tx.ExecContext(ctx,`UPDATE elx_node_inventory
   SET incarnation=$2 WHERE node_id=$1 AND incarnation=$3`,
   out.NodeID,out.NewIncarnation,out.OldIncarnation)
 if err!=nil{return out,err}
 // Preserve paid-profile node/resource ownership while advancing its
 // expected policy epoch. The next policy deployment still requires a
 // verified core readback; an epoch bump is never an automatic enable.
 _,err=tx.ExecContext(ctx,`UPDATE elx_paid_profile_nodes pn
   SET epoch=g.epoch
   FROM elx_rate_grants g
   WHERE pn.node_id=$1 AND pn.node_id=g.node_id
     AND pn.resource_id=g.resource_id`,out.NodeID)
 if err!=nil{return out,err}
 _,err=tx.ExecContext(ctx,`UPDATE elx_core_rotations
  SET state='completed',completed_at=clock_timestamp() WHERE id=$1`,id)
 if err!=nil{return out,err}
 out.State="completed"
 if err=tx.Commit();err!=nil{return CoreRotation{},fmt.Errorf("commit core rotation: %w",err)}
 return out,nil
}
