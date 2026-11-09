package main

import (
	"context"
	"testing"
)

func TestManagedAgentRefusesLoopbackOrMissingLease(t *testing.T) {
	t.Setenv("ELX_AGENT_MANAGED","1")
	t.Setenv("ELX_AGENT_LEASE_REQUIRED","")
	t.Setenv("ELXRAY_POLICY_LOOPBACK","127.0.0.1:10085")
	t.Setenv("ELXRAY_POLICY_SOCKET","/run/elxray/agent.sock")
	if _,err:=openCore();err==nil {t.Fatal("managed agent allowed missing lease flag")}
	t.Setenv("ELX_AGENT_LEASE_REQUIRED","1")
	if _,err:=openCore();err==nil {t.Fatal("managed agent allowed TCP loopback fallback")}
	t.Setenv("ELXRAY_POLICY_LOOPBACK","")
	t.Setenv("ELXRAY_POLICY_SOCKET","")
	if _,err:=openCore();err==nil {t.Fatal("managed agent allowed missing Unix socket")}
	if err:=serveAgent(context.Background(),nil);err==nil {t.Fatal("managed agent started without Unix socket")}
}
