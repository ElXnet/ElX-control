package management

import (
 "errors"
 "testing"
 "time"
 "github.com/ElXnet/ElX-control/internal/elxcontrol/journal"
)
func TestScheduleWindowCalendarAndDST(t *testing.T){
 loc,_:=time.LoadLocation("Europe/Warsaw")
 start,end,err:=scheduleWindow(time.Date(2026,3,29,12,0,0,0,loc),"day","Europe/Warsaw")
 if err!=nil||end.Sub(start)!=23*time.Hour{t.Fatalf("DST window %s to %s: %v",start,end,err)}
 start,end,err=scheduleWindow(time.Date(2026,11,4,12,0,0,0,time.UTC),"week","UTC")
 if err!=nil||start.Weekday()!=time.Monday||end.Sub(start)!=7*24*time.Hour{t.Fatalf("week window %s-%s %v",start,end,err)}
 start,end,err=scheduleWindow(time.Date(2026,2,15,12,0,0,0,time.UTC),"month","UTC")
 if err!=nil||start.Day()!=1||end.Month()!=time.March{t.Fatalf("month window %s-%s %v",start,end,err)}
 for _,zone:=range []string{"../../etc/passwd","/tmp/zone","Bad\\Zone",""}{
  _,_,err=scheduleWindow(time.Now(),"day",zone)
  if !errors.Is(err,ErrSchedule){t.Fatalf("invalid zone %s accepted",zone)}
 }
}
func TestCreateScheduleIdempotentPurchasedBound(t *testing.T){
 ctx,db:=managementPostgres(t)
 e:="00000000-0000-4000-8000-000000000031"
 other:="00000000-0000-4000-8000-000000000032"
 for _,id:=range []string{e,other}{
  if _,err:=db.ExecContext(ctx,"INSERT INTO elx_entitlements(id,active_slots,valid_until) VALUES($1,2,clock_timestamp()+interval '1 year')",id);err!=nil{t.Fatal(err)}
 }
 if _,err:=db.ExecContext(ctx,"INSERT INTO elx_rate_budgets(entitlement_id,up_limit,down_limit) VALUES($1,12500000,12500000)",e);err!=nil{t.Fatal(err)}
 spec:=ScheduleSpec{ScheduleID:"00000000-0000-4000-8000-000000000033",Cadence:"month",Timezone:"UTC",Direction:"total",ThresholdBytes:1_000_000_000,ReducedUp:2500000,ReducedDown:2500000}
 store:=SQLStore{DB:db}
 first,err:=store.CreateSchedule(ctx,e,spec)
 if err!=nil||first.PeriodID==""||first.AlreadyExisted {t.Fatalf("create %+v %v",first,err)}
 second,err:=store.CreateSchedule(ctx,e,spec)
 if err!=nil||second.PeriodID!=first.PeriodID||!second.AlreadyExisted{t.Fatalf("replay %+v %v",second,err)}
 changed:=spec;changed.ThresholdBytes=2
 if _,err:=store.CreateSchedule(ctx,e,changed);!errors.Is(err,journal.ErrConflict){t.Fatalf("ID reuse with changed policy: %v",err)}
 if _,err:=store.CreateSchedule(ctx,other,spec);err==nil{t.Fatal("cross-entitlement reuse accepted")}
 changed=spec;changed.ScheduleID="00000000-0000-4000-8000-000000000034";changed.ReducedDown=12500001
 if _,err:=store.CreateSchedule(ctx,e,changed);!errors.Is(err,ErrSchedule){t.Fatalf("above purchase cap %v",err)}
 var count int
 if err:=db.QueryRowContext(ctx,"SELECT count(*) FROM elx_usage_periods WHERE entitlement_id=$1",e).Scan(&count);err!=nil{t.Fatal(err)}
 if count!=1{t.Fatalf("replay inserted %d periods",count)}
}
