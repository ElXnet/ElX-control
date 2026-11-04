package management

import (
	"context"
	"errors"
	"net/http/httptest"
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
