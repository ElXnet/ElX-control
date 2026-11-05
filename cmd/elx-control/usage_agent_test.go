package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/google/uuid"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/accounting"
)

func TestUsageBindingsRequireCompleteUniqueProvisioning(t *testing.T) {
	tmp:=t.TempDir()
	path:=filepath.Join(tmp,"bindings.json")
	t.Setenv("ELX_USAGE_BINDINGS",path)
	binding:=accounting.RemoteBinding{
		NodeID:uuid.New(),ExecutorID:uuid.New(),Incarnation:uuid.New(),
		AccountingID:uuid.New(),Generation:1,ScheduleID:uuid.New(),
	}
	write:=func(value any){
		data,err:=json.Marshal(value)
		if err!=nil {t.Fatal(err)}
		if err:=os.WriteFile(path,data,0600);err!=nil {t.Fatal(err)}
	}
	write([]accounting.RemoteBinding{binding})
	out,err:=usageBindings()
	if err!=nil || len(out)!=1 || out[0]!=binding {
		t.Fatalf("provisioning rejected: %v %v",out,err)
	}
	write([]accounting.RemoteBinding{binding,binding})
	if _,err:=usageBindings();err==nil {t.Fatal("duplicate node usage binding accepted")}
	invalid:=binding
	invalid.Incarnation=uuid.Nil
	write([]accounting.RemoteBinding{invalid})
	if _,err:=usageBindings();err==nil {t.Fatal("missing core incarnation accepted")}
	write([]accounting.RemoteBinding{})
	if _,err:=usageBindings();err==nil {t.Fatal("empty usage binding list accepted")}
	if err:=os.WriteFile(path,[]byte("garbage"),0600);err!=nil {t.Fatal(err)}
	if _,err:=usageBindings();err==nil {t.Fatal("malformed binding JSON accepted")}
}

func TestUsageAgentValidatesArgumentsBeforeConnecting(t *testing.T) {
	for _,args:=range [][]string{
		{"-interval","0"},
		{"-interval","100ms"},
		{"-interval","2h"},
		{"-interval","invalid"},
		{"unexpected"},
	} {
		if err:=serveUsage(t.Context(),args);err==nil {
			t.Fatalf("invalid usage polling flags accepted: %v",args)
		}
	}
}
