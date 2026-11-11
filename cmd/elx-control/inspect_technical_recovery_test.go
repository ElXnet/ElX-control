package main

import (
	"context"
	"testing"

	"github.com/google/uuid"
)

func TestTechnicalRecoveryAuditReadOnlyClassification(t *testing.T) {
	cases := []struct{
		action,phase string
		expired bool
		want string
	}{
		{"prepare","prepared",false,"await_signed_prepare"},
		{"prepare","prepared",true,"manual_prepare_review"},
		{"install","prepared",false,"await_signed_delivery"},
		{"install","prepared",true,"read_only_core_proof_probe"},
		{"install","installed",true,"read_only_core_proof_probe"},
		{"retire","retiring",true,"read_only_core_proof_probe"},
		{"retire","installed",true,"read_only_core_proof_probe"},
		{"retire","retired",false,"await_signed_delivery"},
		{"install","retiring",true,"manual_quarantine_review"},
		{"unknown","retired",true,"manual_quarantine_review"},
	}
	for _,tc := range cases {
		got:=technicalRecoveryNextStep(tc.action,tc.phase,tc.expired)
		if got!=tc.want {
			t.Fatalf("%s/%s expired=%v produced %s, expected %s",
				tc.action,tc.phase,tc.expired,got,tc.want)
		}
	}
}

func TestTechnicalRecoveryAuditRejectsAmbiguousIdentities(t *testing.T) {
	item:=TechnicalRecoveryAuditRow{
		OperationID:uuid.NewString(),ProfileID:uuid.NewString(),
		ResourceID:uuid.NewString(),ExecutorID:uuid.NewString(),
		Action:"install",ControlPhase:"prepared",NotAfter:1700000015,
	}
	if !validRecoveryAuditRow(item) {
		t.Fatal("valid independent Control intent audit row rejected")
	}
	for _,invalid:=range []TechnicalRecoveryAuditRow{
		func() TechnicalRecoveryAuditRow { x:=item; x.OperationID="";return x }(),
		func() TechnicalRecoveryAuditRow { x:=item; x.ProfileID=uuid.Nil.String();return x }(),
		func() TechnicalRecoveryAuditRow { x:=item; x.ResourceID="not-a-uuid";return x }(),
		func() TechnicalRecoveryAuditRow { x:=item; x.Action="authorize";return x }(),
		func() TechnicalRecoveryAuditRow { x:=item; x.ControlPhase="INSTALLING";return x }(),
		func() TechnicalRecoveryAuditRow { x:=item; x.NotAfter=0;return x }(),
	}{
		if validRecoveryAuditRow(invalid) {
			t.Fatalf("unsafe Control audit row accepted: %+v",invalid)
		}
	}
	if err:=inspectTechnicalRecovery(context.Background(),nil,[]string{uuid.NewString()});err==nil {
		t.Fatal("audit silently ran without independent Control PostgreSQL")
	}
}
