package policytransport

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/ElXnet/ElX-control/internal/elxcontrol/corepolicy"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/journal"
	"github.com/google/uuid"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
)

type technicalRecoveryFakeConn struct {
	response []byte
	confirmations int
	confirmedMethod string
}
func (c *technicalRecoveryFakeConn) Invoke(_ context.Context, method string, request, response any, _ ...grpc.CallOption) error {
	if strings.HasSuffix(method, "/TechnicalRecoveryNext") {
		response.(*wrapperspb.BytesValue).Value = c.response
		return nil
	}
	if strings.HasSuffix(method, "/TechnicalInstallConfirm") ||
		strings.HasSuffix(method, "/TechnicalRetireConfirm") {
		c.confirmations++
		c.confirmedMethod=method
		return nil
	}
	return errors.New("unexpected technical recovery RPC")
}
func (*technicalRecoveryFakeConn) NewStream(context.Context,*grpc.StreamDesc,string,...grpc.CallOption)(grpc.ClientStream,error) {
	return nil,errors.New("unexpected stream")
}

type technicalRecoveryFakeCore struct {
	installed corepolicy.InstallReceipt
	retired corepolicy.RetireReceipt
	failure error
	reads int
}
func (c *technicalRecoveryFakeCore) ReadRecoveredTechnicalInstalledProof(_ context.Context, _, _ string) (corepolicy.InstallReceipt,error) {
	c.reads++
	if c.failure != nil {return corepolicy.InstallReceipt{},c.failure}
	return c.installed,nil
}
func (c *technicalRecoveryFakeCore) ReadRecoveredTechnicalRetiredProof(_ context.Context, _, _ string) (corepolicy.RetireReceipt,error) {
	c.reads++
	if c.failure != nil {return corepolicy.RetireReceipt{},c.failure}
	return c.retired,nil
}

func TestLostACKRecoveryOnlyRelaysPinnedCoreSignatureAndNeverReplaysMutation(t *testing.T) {
	key:=ed25519.NewKeyFromSeed(make([]byte,ed25519.SeedSize))
	pub:=key.Public().(ed25519.PublicKey)
	node,resource,executor,profile,operation:=uuid.New(),uuid.New(),uuid.New(),uuid.New(),uuid.New()
	binding:=Binding{
		Target:journal.Target{NodeID:node.String(),ResourceID:resource.String()},
		ExecutorID:executor.String(),Subscription:"lab",Epoch:9,PublicKey:pub,
	}
	job:=TechnicalRecoveryJob{
		Action:"install",OperationID:operation.String(),ProfileID:profile.String(),
		NodeID:node.String(),ResourceID:resource.String(),
		ExecutorID:executor.String(),SubscriptionID:"lab",AuthorityGeneration:9,
	}
	install:=corepolicy.InstallReceipt{
		Version:1,OperationID:operation,ProfileID:profile,
		NodeID:node,ResourceID:resource,ExecutorID:executor,
		StoreID:uuid.New(),CoreIncarnation:uuid.New(),
		AuthorityGeneration:9,PolicyRevision:1,
		TranscriptSHA256:strings.Repeat("a",64),
	}
	install.Signature=ed25519.Sign(key,install.Transcript())
	encode:=func(js []TechnicalRecoveryJob) []byte {
		t.Helper()
		raw,err:=json.Marshal(js)
		if err!=nil {t.Fatal(err)}
		return raw
	}
	run:=func(j TechnicalRecoveryJob,p corepolicy.InstallReceipt,fail error) (error,*technicalRecoveryFakeConn,*technicalRecoveryFakeCore) {
		conn:=&technicalRecoveryFakeConn{response:encode([]TechnicalRecoveryJob{j})}
		core:=&technicalRecoveryFakeCore{installed:p,failure:fail}
		err:=ApplyTechnicalRecovery(context.Background(),conn,core,[]Binding{binding})
		return err,conn,core
	}
	err,conn,core:=run(job,install,nil)
	if err!=nil || conn.confirmations!=1 ||
		!strings.HasSuffix(conn.confirmedMethod,"/TechnicalInstallConfirm") ||
		core.reads!=1 {
		t.Fatalf("live signed proof recovery did not confirm exact prior outcome: %v %+v %+v",err,conn,core)
	}
	// The retire path has a distinct signed transcript and must not be
	// mistaken for a completed INSTALL or an owner-slot release.
	retireJob:=job
	retireJob.Action="retire"
	retired:=corepolicy.RetireReceipt{
		Version:1,OperationID:operation,ProfileID:profile,
		NodeID:node,ResourceID:resource,ExecutorID:executor,
		StoreID:uuid.New(),CoreIncarnation:uuid.New(),
		AuthorityGeneration:9,PolicyRevision:1,RetireGeneration:2,
		TranscriptSHA256:strings.Repeat("b",64),
	}
	retired.Signature=ed25519.Sign(key,retired.Transcript())
	retireConn:=&technicalRecoveryFakeConn{response:encode([]TechnicalRecoveryJob{retireJob})}
	retireCore:=&technicalRecoveryFakeCore{retired:retired}
	if err:=ApplyTechnicalRecovery(context.Background(),retireConn,retireCore,[]Binding{binding});
		err!=nil || retireConn.confirmations!=1 ||
		!strings.HasSuffix(retireConn.confirmedMethod,"/TechnicalRetireConfirm") ||
		retireCore.reads!=1 {
		t.Fatalf("read-only RETIRE recovery did not deliver pinned proof: %v %+v",err,retireConn)
	}
	retired.Signature=append([]byte(nil),retired.Signature...)
	retired.Signature[0]^=1
	tamperedConn:=&technicalRecoveryFakeConn{response:encode([]TechnicalRecoveryJob{retireJob})}
	if err:=ApplyTechnicalRecovery(context.Background(),tamperedConn,
		&technicalRecoveryFakeCore{retired:retired},[]Binding{binding});
		status.Code(err)!=codes.PermissionDenied || tamperedConn.confirmations!=0 {
		t.Fatalf("forged retired recovery was accepted: %v",err)
	}
	forged:=install
	forged.Signature=append([]byte(nil),install.Signature...)
	forged.Signature[0]^=1
	err,conn,_=run(job,forged,nil)
	if status.Code(err)!=codes.PermissionDenied || conn.confirmations!=0 {
		t.Fatalf("forged core recovery proof was accepted: %v",err)
	}
	foreign:=job
	foreign.ExecutorID=uuid.NewString()
	err,conn,core=run(foreign,install,nil)
	if status.Code(err)!=codes.PermissionDenied || conn.confirmations!=0 || core.reads!=0 {
		t.Fatalf("foreign recovery request reached core: %v",err)
	}
	err,conn,_=run(job,install,status.Error(codes.FailedPrecondition,"operation not safely completed"))
	if status.Code(err)!=codes.FailedPrecondition || conn.confirmations!=0 {
		t.Fatalf("unproven expired operation was falsely confirmed: %v",err)
	}
}
