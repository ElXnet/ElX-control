package management

import (
	"context"
	"errors"
	"net/http/httptest"
	"net/http"
	"bytes"
	"strings"
	"testing"
)

const (
	testEntitlement="00000000-0000-4000-8000-000000000001"
	testOther="00000000-0000-4000-8000-000000000002"
	testOwner="00000000-0000-4000-8000-000000000003"
)

type fakeStore struct {
	drainCalls int
	reconcileCalls int
	err error
}
func (f *fakeStore) List(_ context.Context, after string,limit int)(Page,error){
	return Page{Items:[]Entitlement{{ID:testEntitlement,ActiveSlots:2}},NextCursor:after},f.err
}
func (f *fakeStore) Get(_ context.Context,id string)(Detail,error){
	return Detail{Entitlement:Entitlement{ID:id}},f.err
}
func (f *fakeStore) QueueDrain(_ context.Context,entitlement,owner string)error{
	f.drainCalls++
	if entitlement!=testEntitlement||owner!=testOwner{return ErrNotFound}
	return f.err
}
func (f *fakeStore) RevokeDevice(_ context.Context,entitlement,device string)(RevokeResult,error) {
	if entitlement!=testEntitlement || device!=testOther {return RevokeResult{},ErrNotFound}
	if f.err!=nil {return RevokeResult{},f.err}
	return RevokeResult{DeviceID:device,Revoked:true,DrainQueued:1},nil
}
func (f *fakeStore) CreateSchedule(_ context.Context,id string,spec ScheduleSpec)(ScheduleCreated,error){
 if id!=testEntitlement {return ScheduleCreated{},ErrNotFound}
 if f.err!=nil{return ScheduleCreated{},f.err}
 return ScheduleCreated{ScheduleID:spec.ScheduleID,PeriodID:testOther},nil
}
func (f *fakeStore) Reconcile(_ context.Context,id string)(ReconcileResult,error){
	f.reconcileCalls++
	return ReconcileResult{EntitlementID:id,Active:true,Pending:2},f.err
}
func serve(t *testing.T,f *fakeStore,method,path string)*httptest.ResponseRecorder{
	t.Helper()
	w:=httptest.NewRecorder()
	Handler(f).ServeHTTP(w,httptest.NewRequest(method,path,nil))
	return w
}
func TestManagementReadOnlyAndNoSecrets(t *testing.T){
	f:=&fakeStore{}
	w:=serve(t,f,"GET","/v1/entitlements?limit=50")
	if w.Code!=200||!strings.Contains(w.Body.String(),testEntitlement){t.Fatalf("list: %d %s",w.Code,w.Body.String())}
	w=serve(t,f,"GET","/v1/entitlements/"+testEntitlement)
	if w.Code!=200||!strings.Contains(w.Body.String(),"activeSlots"){t.Fatalf("detail: %d %s",w.Code,w.Body.String())}
	if w.Header().Get("Cache-Control")!="no-store"{t.Fatal("management responses must not be cached")}
	if f.drainCalls!=0||f.reconcileCalls!=0{t.Fatal("GET mutated control state")}
}
func TestManagementRejectsBadIDsMethodsAndRanges(t *testing.T){
	f:=&fakeStore{}
	for _,path:=range []string{
		"/v1/entitlements?limit=101",
		"/v1/entitlements?after=not-uuid",
		"/v1/entitlements/"+testEntitlement+"/sessions/not-uuid/drain",
		"/v1/entitlements/not-uuid/reconcile-fup",
	}{
		method:="GET"
		if strings.Contains(path,"/drain")||strings.Contains(path,"/reconcile-fup"){method="POST"}
		w:=serve(t,f,method,path)
		if w.Code!=400{t.Fatalf("%s returned %d",path,w.Code)}
	}
	w:=serve(t,f,"GET","/v1/entitlements/"+testEntitlement+"/sessions/"+testOwner+"/drain")
	if w.Code!=405{t.Fatalf("GET must not drain: %d",w.Code)}
	if f.drainCalls!=0||f.reconcileCalls!=0{t.Fatal("invalid requests executed mutations")}
}
func TestDrainOnlyQueuesAndNeverClaimsRelease(t *testing.T){
	f:=&fakeStore{}
	w:=serve(t,f,"POST","/v1/entitlements/"+testEntitlement+"/sessions/"+testOwner+"/drain")
	if w.Code!=202||!strings.Contains(w.Body.String(),"pending-signed-core-fence")||strings.Contains(w.Body.String(),`"released":true`){t.Fatalf("unsafe response: %d %s",w.Code,w.Body.String())}
	if f.drainCalls!=1{t.Fatalf("calls=%d",f.drainCalls)}
	w=serve(t,f,"POST","/v1/entitlements/"+testOther+"/sessions/"+testOwner+"/drain")
	if w.Code!=404{t.Fatalf("cross-entitlement drain: %d",w.Code)}
}
func TestErrorsFailClosed(t *testing.T){
	f:=&fakeStore{err:errors.New("database password must not leak")}
	w:=serve(t,f,"GET","/v1/entitlements")
	if w.Code!=503||strings.Contains(w.Body.String(),"password"){t.Fatalf("database error leaked: %d %s",w.Code,w.Body.String())}
	w=serve(t,f,"POST","/v1/entitlements/"+testEntitlement+"/sessions/"+testOwner+"/drain")
	if w.Code!=503{t.Fatalf("write error status %d",w.Code)}
}
func TestFUPReconcileIsExplicit(t *testing.T){
	f:=&fakeStore{}
	w:=serve(t,f,"POST","/v1/entitlements/"+testEntitlement+"/reconcile-fup")
	if w.Code!=200||!strings.Contains(w.Body.String(),`"pending":2`){t.Fatalf("FUP %d %s",w.Code,w.Body.String())}
	if f.reconcileCalls!=1{t.Fatalf("FUP calls=%d",f.reconcileCalls)}
}

func TestDeviceRevokeMethodAndOwnership(t *testing.T){
	f:=&fakeStore{}
	path:="/v1/entitlements/"+testEntitlement+"/devices/"+testOther+"/revoke"
	w:=serve(t,f,"GET",path)
	if w.Code!=405 {t.Fatalf("GET was allowed to revoke: %d",w.Code)}
	w=serve(t,f,"POST",path)
	if w.Code!=202 || !strings.Contains(w.Body.String(),`"drainQueued":1`) || strings.Contains(w.Body.String(),`"released":true`) {
		t.Fatalf("unsafe revoke response %d %s",w.Code,w.Body.String())
	}
	w=serve(t,f,"POST","/v1/entitlements/"+testOther+"/devices/"+testOther+"/revoke")
	if w.Code!=404 {t.Fatalf("cross-entitlement revoke: %d",w.Code)}
	w=serve(t,f,"POST","/v1/entitlements/"+testEntitlement+"/devices/bad/revoke")
	if w.Code!=400 {t.Fatalf("bad device id: %d",w.Code)}
}

func TestFUPEndpointRequestValidation(t *testing.T){
 f:=&fakeStore{}
 id:="00000000-0000-4000-8000-000000000044"
 good:=`{"scheduleId":"`+id+`","cadence":"month","timezone":"UTC","direction":"total","thresholdBytes":1000000,"reducedUp":1000,"reducedDown":1000}`
 path:="/v1/entitlements/"+testEntitlement+"/fup-schedules"
 for _,body:=range []string{
  `{"unknown":"x"}`,`{"scheduleId":"bad"}`,good+"{}",
  `{"scheduleId":"`+id+`","cadence":"month","timezone":"UTC","direction":"total","thresholdBytes":"NaN","reducedUp":1000,"reducedDown":1000}`,
 }{
  w:=httptest.NewRecorder()
  req:=httptest.NewRequest(http.MethodPost,path,bytes.NewBufferString(body))
  req.Header.Set("Content-Type","application/json")
  Handler(f).ServeHTTP(w,req)
  if w.Code!=400 {t.Fatalf("invalid body accepted %d %s",w.Code,w.Body.String())}
 }
 w:=httptest.NewRecorder()
 req:=httptest.NewRequest(http.MethodPost,path,bytes.NewBufferString(good))
 req.Header.Set("Content-Type","application/json")
 Handler(f).ServeHTTP(w,req)
 if w.Code!=201 || !strings.Contains(w.Body.String(),id){t.Fatalf("valid schedule: %d %s",w.Code,w.Body.String())}
 w=serve(t,f,"GET",path)
 if w.Code!=405{t.Fatalf("GET generated schedule %d",w.Code)}
}
