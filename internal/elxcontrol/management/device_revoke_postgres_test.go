package management

import (
 "context"
 "testing"
)

func TestManagementRevokePostgresBoundAndUnbound(t *testing.T){
 ctx,db:=managementPostgres(t)
 entitlement:="00000000-0000-4000-8000-000000000011"
 other:="00000000-0000-4000-8000-000000000012"
 device:="00000000-0000-4000-8000-000000000013"
 node:="00000000-0000-4000-8000-000000000014"
 op:="00000000-0000-4000-8000-000000000015"
 sessionID:="00000000-0000-4000-8000-000000000016"
 profile:="00000000-0000-4000-8000-000000000017"
 incarnation:="00000000-0000-4000-8000-000000000018"
 for _,id:=range []string{entitlement,other}{
  if _,err:=db.ExecContext(ctx,"INSERT INTO elx_entitlements(id,active_slots,valid_until) VALUES($1,2,clock_timestamp()+interval '1 day')",id);err!=nil{t.Fatal(err)}
 }
 if _,err:=db.ExecContext(ctx,"INSERT INTO elx_devices(id,entitlement_id,key_generation) VALUES($1,$2,1)",device,entitlement);err!=nil{t.Fatal(err)}
 if _,err:=db.ExecContext(ctx,`INSERT INTO elx_session_owners
  (id,entitlement_id,device_id,node_id,operation_id,generation,key_generation,proof_hash,state,profile_id,core_incarnation)
  VALUES ($1,$2,$3,$4,$5,1,1,decode(repeat('ab',32),'hex'),'active',$6,$7)`,sessionID,entitlement,device,node,op,profile,incarnation);err!=nil{t.Fatal(err)}
 s:=SQLStore{DB:db}
 if _,err:=s.RevokeDevice(ctx,other,device);err!=ErrNotFound{t.Fatalf("cross-entitlement revocation accepted: %v",err)}
 result,err:=s.RevokeDevice(ctx,entitlement,device)
 if err!=nil||!result.Revoked||result.DrainQueued!=1||result.Undrainable!=0{t.Fatalf("revoke result %+v %v",result,err)}
 var revoked bool
 var state string
 if err=db.QueryRowContext(ctx,"SELECT revoked FROM elx_devices WHERE id=$1",device).Scan(&revoked);err!=nil{t.Fatal(err)}
 if err=db.QueryRowContext(ctx,"SELECT state FROM elx_session_owners WHERE id=$1",sessionID).Scan(&state);err!=nil{t.Fatal(err)}
 if !revoked||state!="draining"{t.Fatalf("device state revoked=%v session=%s",revoked,state)}
 duplicate,err:=s.RevokeDevice(ctx,entitlement,device)
 if err!=nil||!duplicate.AlreadyRevoked||duplicate.DrainQueued!=1{t.Fatalf("revoke replay: %+v %v",duplicate,err)}
}

func TestRevokeDoesNotReleaseUnboundSession(t *testing.T){
 ctx,db:=managementPostgres(t)
 e:="00000000-0000-4000-8000-000000000021"
 d:="00000000-0000-4000-8000-000000000022"
 if _,err:=db.ExecContext(ctx,"INSERT INTO elx_entitlements(id,active_slots,valid_until) VALUES($1,2,clock_timestamp()+interval '1 day')",e);err!=nil{t.Fatal(err)}
 if _,err:=db.ExecContext(ctx,"INSERT INTO elx_devices(id,entitlement_id,key_generation) VALUES($1,$2,1)",d,e);err!=nil{t.Fatal(err)}
 if _,err:=db.ExecContext(ctx,`INSERT INTO elx_session_owners
 (id,entitlement_id,device_id,node_id,operation_id,generation,key_generation,proof_hash,state)
 VALUES($1,$2,$3,$4,$5,1,1,decode(repeat('ab',32),'hex'),'unknown')`,
 "00000000-0000-4000-8000-000000000023",e,d,
 "00000000-0000-4000-8000-000000000024","00000000-0000-4000-8000-000000000025");err!=nil{t.Fatal(err)}
 result,err:=(SQLStore{DB:db}).RevokeDevice(context.Background(),e,d)
 if err!=nil||result.Undrainable!=1||result.DrainQueued!=0{t.Fatalf("unbound result: %+v %v",result,err)}
 var state string
 if err:=db.QueryRowContext(ctx,"SELECT state FROM elx_session_owners WHERE device_id=$1",d).Scan(&state);err!=nil{t.Fatal(err)}
 if state!="unknown"{t.Fatalf("unsafe slot release: %s",state)}
}
