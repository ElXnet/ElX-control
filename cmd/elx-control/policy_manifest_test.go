package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/ElXnet/ElX-control/internal/elxcontrol/journal"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/policytransport"
	"github.com/google/uuid"
)

func TestTrustedPolicyManifestFileBoundary(t *testing.T) {
	dir:=t.TempDir()
	path:=filepath.Join(dir,"policy.json")
	t.Setenv("ELX_POLICY_BINDING",path)
	key,_,err:=ed25519.GenerateKey(nil)
	if err!=nil{t.Fatal(err)}
	b:=policytransport.Binding{
		Target:journal.Target{NodeID:uuid.NewString(),ResourceID:uuid.NewString()},
		Subscription:"pinned-vless-id",Epoch:1,PublicKey:key,
	}
	data,err:=json.Marshal([]policytransport.Binding{b})
	if err!=nil{t.Fatal(err)}
	if err:=os.WriteFile(path,data,0600);err!=nil{t.Fatal(err)}
	list,err:=loadBindings()
	if err!=nil||len(list)!=1||list[0].Subscription!=b.Subscription {
		t.Fatalf("valid trusted policy manifest rejected: %+v %v",list,err)
	}
	if runtime.GOOS!="windows" {
		if err:=os.Chmod(path,0666);err!=nil{t.Fatal(err)}
		if _,err:=loadBindings();err==nil{t.Fatal("world-writable policy manifest accepted")}
		if err:=os.Chmod(path,0600);err!=nil{t.Fatal(err)}
		link:=filepath.Join(dir,"policy-link.json")
		if err:=os.Symlink(path,link);err!=nil{t.Fatal(err)}
		t.Setenv("ELX_POLICY_BINDING",link)
		if _,err:=loadBindings();err==nil{t.Fatal("policy manifest symlink accepted")}
		t.Setenv("ELX_POLICY_BINDING",path)
	}
	if err:=os.WriteFile(path,bytes.Repeat([]byte("z"),1<<20+1),0600);err!=nil{t.Fatal(err)}
	if _,err:=loadBindings();err==nil{t.Fatal("oversized policy manifest accepted")}
	if err:=os.WriteFile(path,[]byte("garbage"),0600);err!=nil{t.Fatal(err)}
	if _,err:=loadBindings();err==nil{t.Fatal("malformed policy manifest accepted")}
}
