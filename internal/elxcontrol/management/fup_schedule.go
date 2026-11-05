package management

import (
 "context"
 "database/sql"
 "errors"
 "math"
 "strings"
 "time"

 "github.com/google/uuid"
 "github.com/ElXnet/ElX-control/internal/elxcontrol/journal"
)

var ErrSchedule=errors.New("invalid FUP schedule or purchased limits")

type ScheduleSpec struct {
 ScheduleID string `json:"scheduleId"`
 Cadence string `json:"cadence"`
 Timezone string `json:"timezone"`
 Direction string `json:"direction"`
 ThresholdBytes int64 `json:"thresholdBytes"`
 ReducedUp int64 `json:"reducedUp"`
 ReducedDown int64 `json:"reducedDown"`
}
type ScheduleCreated struct {
 ScheduleID string `json:"scheduleId"`
 PeriodID string `json:"periodId"`
 StartsAt time.Time `json:"startsAt"`
 EndsAt time.Time `json:"endsAt"`
 AlreadyExisted bool `json:"alreadyExisted"`
}

func validZone(zone string) bool {
 if zone=="UTC" {return true}
 if len(zone)<3||len(zone)>128||zone[0]=='/'||strings.Contains(zone,"..")||!strings.Contains(zone,"/"){return false}
 for _,ch:=range zone {
  if (ch>='a'&&ch<='z')||(ch>='A'&&ch<='Z')||(ch>='0'&&ch<='9')||ch=='/'||ch=='_'||ch=='+'||ch=='-' {continue}
  return false
 }
 return true
}
func validSchedule(spec ScheduleSpec) bool {
 return canonical(spec.ScheduleID) &&
  (spec.Cadence=="day"||spec.Cadence=="week"||spec.Cadence=="month") &&
  validZone(spec.Timezone) &&
  (spec.Direction=="up"||spec.Direction=="down"||spec.Direction=="total") &&
  spec.ThresholdBytes>0 && spec.ThresholdBytes<math.MaxInt64 &&
  spec.ReducedUp>0 && spec.ReducedUp<=1<<40 &&
  spec.ReducedDown>0 && spec.ReducedDown<=1<<40
}

func scheduleWindow(now time.Time, cadence, zone string)(time.Time,time.Time,error){
 if now.IsZero()||!validZone(zone){return time.Time{},time.Time{},ErrSchedule}
 loc,err:=time.LoadLocation(zone)
 if err!=nil{return time.Time{},time.Time{},ErrSchedule}
 local:=now.In(loc)
 y,m,d:=local.Date()
 switch cadence{
 case "day":
 case "week": d-=(int(local.Weekday())+6)%7
 case "month":d=1
 default:return time.Time{},time.Time{},ErrSchedule
 }
 start:=time.Date(y,m,d,0,0,0,0,loc)
 var end time.Time
 switch cadence {
 case "day":end=start.AddDate(0,0,1)
 case "week":end=start.AddDate(0,0,7)
 case "month":end=start.AddDate(0,1,0)
 }
 if !end.After(start)||now.Before(start)||!now.Before(end) ||
  start.In(loc).Hour()!=0||end.In(loc).Hour()!=0{
  return time.Time{},time.Time{},ErrSchedule
 }
 return start.UTC(),end.UTC(),nil
}

// CreateSchedule is a privileged operation for already purchased entitlements.
// It cannot raise speeds or create an unlimited FUP. A caller-controlled
// ScheduleID makes retries idempotent, including after a controller restart.
func (s SQLStore) CreateSchedule(ctx context.Context, entitlement string, spec ScheduleSpec)(ScheduleCreated,error){
 return s.createSchedule(ctx,entitlement,spec,0)
}

// CreateUserSchedule permits only tighter user-defined caps and bounds the
// number of schedules to prevent unbounded accounting/maintenance work.
func (s SQLStore) CreateUserSchedule(ctx context.Context, entitlement string, spec ScheduleSpec)(ScheduleCreated,error){
 return s.createSchedule(ctx,entitlement,spec,3)
}
func (s SQLStore) createSchedule(ctx context.Context, entitlement string, spec ScheduleSpec,maxSchedules int)(ScheduleCreated,error){
 out:=ScheduleCreated{ScheduleID:spec.ScheduleID}
 if s.DB==nil||!canonical(entitlement)||!validSchedule(spec){return out,ErrSchedule}
 tx,err:=s.DB.BeginTx(ctx,&sql.TxOptions{Isolation:sql.LevelReadCommitted})
 if err!=nil{return out,err}
 defer tx.Rollback()
 // Lock entitlement before rate rows and schedule creation. This serializes
 // provisioning with any future entitlement ownership mutations.
 var found string
 err=tx.QueryRowContext(ctx,"SELECT id::text FROM elx_entitlements WHERE id=$1 FOR UPDATE",entitlement).Scan(&found)
 if errors.Is(err,sql.ErrNoRows){return out,ErrNotFound}
 if err!=nil{return out,err}
 var limitUp,limitDown int64
 err=tx.QueryRowContext(ctx,"SELECT up_limit,down_limit FROM elx_rate_budgets WHERE entitlement_id=$1 FOR UPDATE",entitlement).Scan(&limitUp,&limitDown)
 if errors.Is(err,sql.ErrNoRows){return out,ErrSchedule}
 if err!=nil{return out,err}
 if limitUp<=0||limitDown<=0||spec.ReducedUp>limitUp||spec.ReducedDown>limitDown{
  return out,ErrSchedule
 }
 // Stable idempotency key: never reinterpret a previously issued schedule ID
 // as a different entitlement, cadence, direction or reduced rate.
 var oldEntitlement,oldCadence,oldZone,oldDirection string
 var oldThreshold,oldUp,oldDown int64
 err=tx.QueryRowContext(ctx,`SELECT s.entitlement_id::text,s.cadence,s.timezone_name,
 p.direction,p.threshold_bytes,p.reduced_up,p.reduced_down,p.id::text
 FROM elx_period_schedules s JOIN elx_usage_periods p ON p.id=s.current_period_id
 WHERE s.id=$1`,spec.ScheduleID).Scan(&oldEntitlement,&oldCadence,&oldZone,&oldDirection,&oldThreshold,&oldUp,&oldDown,&out.PeriodID)
 if err==nil {
  if oldEntitlement!=entitlement||oldCadence!=spec.Cadence||oldZone!=spec.Timezone||
   oldDirection!=spec.Direction||oldThreshold!=spec.ThresholdBytes||
   oldUp!=spec.ReducedUp||oldDown!=spec.ReducedDown {
   return ScheduleCreated{},journal.ErrConflict
  }
  if err=tx.QueryRowContext(ctx,"SELECT starts_at,ends_at FROM elx_usage_periods WHERE id=$1",out.PeriodID).Scan(&out.StartsAt,&out.EndsAt);err!=nil{return ScheduleCreated{},err}
  out.AlreadyExisted=true
  return out,tx.Commit()
 }
 if !errors.Is(err,sql.ErrNoRows){return out,err}
 if maxSchedules>0 {
  var count int
  if err=tx.QueryRowContext(ctx,"SELECT count(*) FROM elx_period_schedules WHERE entitlement_id=$1",entitlement).Scan(&count);err!=nil{return out,err}
  if count>=maxSchedules{return out,ErrSchedule}
 }
 var now time.Time
 if err=tx.QueryRowContext(ctx,"SELECT clock_timestamp()").Scan(&now);err!=nil{return out,err}
 out.StartsAt,out.EndsAt,err=scheduleWindow(now,spec.Cadence,spec.Timezone)
 if err!=nil{return out,err}
 id,err:=uuid.NewRandom()
 if err!=nil{return out,err}
 out.PeriodID=id.String()
 _,err=tx.ExecContext(ctx,`INSERT INTO elx_usage_periods
 (id,entitlement_id,starts_at,ends_at,direction,threshold_bytes,reduced_up,reduced_down)
 VALUES($1,$2,$3,$4,$5,$6,$7,$8)`,id,entitlement,out.StartsAt,out.EndsAt,spec.Direction,spec.ThresholdBytes,spec.ReducedUp,spec.ReducedDown)
 if err!=nil{return out,err}
 _,err=tx.ExecContext(ctx,`INSERT INTO elx_period_schedules
 (id,entitlement_id,cadence,timezone_name,current_period_id,enabled)
 VALUES($1,$2,$3,$4,$5,false)`,spec.ScheduleID,entitlement,spec.Cadence,spec.Timezone,id)
 if err!=nil{return out,err}
 _,err=tx.ExecContext(ctx,"UPDATE elx_usage_periods SET schedule_id=$2 WHERE id=$1",id,spec.ScheduleID)
 if err!=nil{return out,err}
 return out,tx.Commit()
}
