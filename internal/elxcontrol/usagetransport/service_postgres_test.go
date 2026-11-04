package usagetransport

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"database/sql"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"math/big"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/accounting"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/corepolicy"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/journal"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/policytransport"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/fencetransport"
	"github.com/ElXnet/ElX-control/internal/elxcontrol/session"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/wrapperspb"
	"google.golang.org/protobuf/types/known/emptypb"
)

func testRemoteDB(t *testing.T) (context.Context, *sql.DB) {
	t.Helper()
	dsn := os.Getenv("ELX_TEST_POSTGRES_DSN")
	if dsn == "" { t.Skip("requires ELX_TEST_POSTGRES_DSN") }
	ctx, cancel := context.WithTimeout(context.Background(), 25*time.Second)
	t.Cleanup(cancel)
	cfg, err := pgx.ParseConfig(dsn)
	if err != nil { t.Fatal(err) }
	admin := stdlib.OpenDB(*cfg)
	t.Cleanup(func(){admin.Close()})
	randomID := uuid.New()
	schema := "elx_remote_" + hex.EncodeToString(randomID[:8])
	_, err = admin.ExecContext(ctx, "CREATE SCHEMA " + schema)
	if err != nil { t.Fatal(err) }
	t.Cleanup(func(){
		c, done := context.WithTimeout(context.Background(), 10*time.Second)
		defer done()
		if _, err := admin.ExecContext(c, "DROP SCHEMA "+schema+" CASCADE"); err != nil { t.Error(err) }
	})
	cfg.RuntimeParams["search_path"] = schema
	db := stdlib.OpenDB(*cfg)
	t.Cleanup(func(){db.Close()})
	if err := journal.Migrate(ctx, db); err != nil { t.Fatal(err) }
	return ctx, db
}

func testCerts(t *testing.T, valid, other uuid.UUID) (*x509.CertPool, tls.Certificate, tls.Certificate, tls.Certificate) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil { t.Fatal(err) }
	now := time.Now()
	ca := &x509.Certificate{
		SerialNumber:big.NewInt(1), Subject:pkix.Name{CommonName:"ElX Test CA"},
		NotBefore:now.Add(-time.Hour), NotAfter:now.Add(time.Hour),
		IsCA:true, BasicConstraintsValid:true, KeyUsage:x509.KeyUsageCertSign|x509.KeyUsageCRLSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, ca, ca, &key.PublicKey, key)
	if err != nil { t.Fatal(err) }
	parent, err := x509.ParseCertificate(der)
	if err != nil { t.Fatal(err) }
	roots := x509.NewCertPool()
	roots.AddCert(parent)
	create := func(serial int64, node uuid.UUID, server bool) tls.Certificate {
		leafKey, err := ecdsa.GenerateKey(elliptic.P256(),rand.Reader)
		if err != nil { t.Fatal(err) }
		cert := &x509.Certificate{
			SerialNumber:big.NewInt(serial), NotBefore:now.Add(-time.Hour),
			NotAfter:now.Add(time.Hour), KeyUsage:x509.KeyUsageDigitalSignature,
			BasicConstraintsValid:true,
		}
		if server {
			cert.IPAddresses=[]net.IP{net.ParseIP("127.0.0.1")}
			cert.ExtKeyUsage=[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}
		} else {
			u, err := url.Parse("spiffe://elxnet/node/"+node.String())
			if err != nil { t.Fatal(err) }
			cert.URIs=[]*url.URL{u}
			cert.ExtKeyUsage=[]x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}
		}
		der, err := x509.CreateCertificate(rand.Reader,cert,parent,&leafKey.PublicKey,key)
		if err != nil { t.Fatal(err) }
		return tls.Certificate{Certificate:[][]byte{der},PrivateKey:leafKey}
	}
	return roots,create(2,uuid.Nil,true),create(3,valid,false),create(4,other,false)
}

type rateBarrierTestCore struct { private ed25519.PrivateKey }
func (c rateBarrierTestCore) ProveRateBarrier(_ context.Context,req corepolicy.RateBarrierRequest,
	pinned ed25519.PublicKey)([]byte,error){
	if string(pinned)!=string(c.private.Public().(ed25519.PublicKey)) ||
		req.CoreRevision!=req.Revision+1 {
		return nil,fmt.Errorf("rate barrier core identity or revision mismatch")
	}
	return ed25519.Sign(c.private,corepolicy.BarrierTranscript(req)),nil
}

type proofCore struct {
	key ed25519.PrivateKey
	incarnation uuid.UUID
	seq int64
	sig []byte
}

func (c *proofCore) ReadUsageEvidence(_ context.Context, subscription, nonce string) ([]byte,error) {
	c.seq++
	data := append([]byte{}, c.incarnation[:]...)
	data = binary.BigEndian.AppendUint64(data,uint64(c.seq))
	data = binary.BigEndian.AppendUint64(data,uint64(time.Now().UTC().UnixNano()))
	data = binary.BigEndian.AppendUint64(data,40)
	data = binary.BigEndian.AppendUint64(data,70)
	c.sig = append(data,ed25519.Sign(c.key,
		fmt.Appendf(nil,"elx-usage-v1\n%x\n%x\n%x",nonce,subscription,data))...)
	return c.sig,nil
}

type fakeProfileDrainer struct { key ed25519.PrivateKey }
func (d fakeProfileDrainer) DrainProfile(_ context.Context, f session.Fence,
	pinned ed25519.PublicKey) ([]byte,error) {
	if string(pinned)!=string(d.key.Public().(ed25519.PublicKey)) {
		return nil,fmt.Errorf("ElXray core key differs from Control binding")
	}
	return ed25519.Sign(d.key,session.FenceTranscript(f)),nil
}

func TestGRPCSignedAccountingRequiresVerifiedNodeAndCore(t *testing.T) {
	ctx, db := testRemoteDB(t)
	entitlement, schedule, period := uuid.New(),uuid.New(),uuid.New()
	now := time.Now().UTC().Truncate(24*time.Hour)
	start, end := now, now.AddDate(0,0,1)
	_,err := db.ExecContext(ctx,`INSERT INTO elx_entitlements(id,active_slots,valid_until)
		VALUES($1,2,clock_timestamp()+interval '1 day')`,entitlement)
	if err != nil { t.Fatal(err) }
	_,err=db.ExecContext(ctx,`INSERT INTO elx_rate_budgets VALUES($1,100,100)`,entitlement)
	if err != nil { t.Fatal(err) }
	_,err=db.ExecContext(ctx,`INSERT INTO elx_usage_periods
		(id,entitlement_id,starts_at,ends_at,direction,threshold_bytes,reduced_up,reduced_down)
		VALUES($1,$2,$3,$4,'total',50,20,20)`,period,entitlement,start,end)
	if err != nil { t.Fatal(err) }
	_,err=db.ExecContext(ctx,`INSERT INTO elx_period_schedules
		(id,entitlement_id,cadence,timezone_name,current_period_id,enabled)
		VALUES($1,$2,'day','UTC',$3,false)`,schedule,entitlement,period)
	if err != nil { t.Fatal(err) }
	_,err=db.ExecContext(ctx,`UPDATE elx_usage_periods SET schedule_id=$2 WHERE id=$1`,period,schedule)
	if err != nil { t.Fatal(err) }

	binding := accounting.RemoteBinding{
		NodeID:uuid.New(),ExecutorID:uuid.New(),Incarnation:uuid.New(),
		AccountingID:uuid.New(),Generation:1,ScheduleID:schedule,
	}
	pub,key,err:=ed25519.GenerateKey(rand.Reader)
	if err != nil { t.Fatal(err) }
	sub:="signed-usage-test"
	_,err=db.ExecContext(ctx,`INSERT INTO elx_core_identities
		(node_id,incarnation,public_key) VALUES($1,$2,$3)`,
		binding.NodeID,binding.Incarnation,[]byte(pub))
	if err != nil { t.Fatal(err) }
	_,err=db.ExecContext(ctx,`INSERT INTO elx_accounting_streams
		(node_id,executor_id,incarnation,accounting_id,generation,period_id)
		VALUES($1,$2,$3,$4,$5,$6)`,
		binding.NodeID,binding.ExecutorID,binding.Incarnation,binding.AccountingID,1,period)
	if err != nil { t.Fatal(err) }
	_,err=db.ExecContext(ctx,`INSERT INTO elx_accounting_assignments
		(node_id,executor_id,incarnation,accounting_id,generation,period_id,subscription_id)
		VALUES($1,$2,$3,$4,$5,$6,$7)`,
		binding.NodeID,binding.ExecutorID,binding.Incarnation,binding.AccountingID,1,period,sub)
	if err != nil { t.Fatal(err) }

	// Leasing requires a trusted, active rate-grant assignment.
	leaseResource:=uuid.New()
	_,err=db.ExecContext(ctx,`INSERT INTO elx_operation_targets(node_id,resource_id)
		VALUES($1,$2)`,binding.NodeID,leaseResource)
	if err!=nil {t.Fatal(err)}
	_,err=db.ExecContext(ctx,`INSERT INTO elx_rate_grants
		(entitlement_id,node_id,resource_id,committed_up,committed_down,epoch,barrier_public_key)
		VALUES($1,$2,$3,100,100,1,$4)`,entitlement,binding.NodeID,leaseResource,[]byte(pub))
	if err!=nil {t.Fatal(err)}
	leasePub,leasePrivate,err:=ed25519.GenerateKey(rand.Reader)
	if err!=nil {t.Fatal(err)}
	seedPath:=filepath.Join(t.TempDir(),"lease-seed")
	if err:=os.WriteFile(seedPath,[]byte(hex.EncodeToString(leasePrivate.Seed())),0600);err!=nil {t.Fatal(err)}
	t.Setenv("ELX_CONTROL_LEASE_SEED_FILE",seedPath)

	roots,serverCert,clientCert,foreignCert:=testCerts(t,binding.NodeID,uuid.New())
	lis,err:=net.Listen("tcp","127.0.0.1:0")
	if err != nil { t.Fatal(err) }
	srv:=grpc.NewServer(grpc.Creds(credentials.NewTLS(&tls.Config{
		Certificates:[]tls.Certificate{serverCert},ClientAuth:tls.RequireAndVerifyClientCert,
		ClientCAs:roots,MinVersion:tls.VersionTLS13,
	})))
	if err := Register(srv,db); err != nil { t.Fatal(err) }
	if err := fencetransport.Register(srv,db); err != nil { t.Fatal(err) }
	if err:=policytransport.Register(srv,db,policytransport.Binding{
		Target:journal.Target{NodeID:binding.NodeID.String(),ResourceID:leaseResource.String()},
		Subscription:sub,Epoch:1,PublicKey:pub,
	});err!=nil {t.Fatal(err)}
	go srv.Serve(lis)
	t.Cleanup(func(){srv.Stop();lis.Close()})
	dial:=func(cert tls.Certificate)*grpc.ClientConn{
		conn,err:=grpc.NewClient(lis.Addr().String(),grpc.WithTransportCredentials(
			credentials.NewTLS(&tls.Config{RootCAs:roots,Certificates:[]tls.Certificate{cert},
				MinVersion:tls.VersionTLS13})))
		if err != nil { t.Fatal(err) }
		t.Cleanup(func(){conn.Close()})
		return conn
	}
	good,foreign:=dial(clientCert),dial(foreignCert)
	leaseInput,err:=json.Marshal(policytransport.LeaseRequest{
		ResourceID:leaseResource.String(),Subscription:sub,
	})
	if err!=nil {t.Fatal(err)}
	var leaseWire wrapperspb.BytesValue
	leaseRoute:="/elx.node.v1.PolicyDelivery/Lease"
	if err:=foreign.Invoke(ctx,leaseRoute,wrapperspb.Bytes(leaseInput),&leaseWire);
		status.Code(err)!=codes.PermissionDenied {
		t.Fatalf("foreign mTLS certificate received Control lease: %v",err)
	}
	// An unenrolled FUP schedule is staged and must not interrupt a
	// paying VPN subscription. Once enabled, leases require current signed
	// accounting bound to every active rate grant.
	if err:=good.Invoke(ctx,leaseRoute,wrapperspb.Bytes(leaseInput),&leaseWire);err!=nil {
		t.Fatalf("eligible node did not get a signed Control lease: %v",err)
	}
	// The same mTLS endpoint carries rate barriers, but only after the
	// journal confirms a policy update. The test core signs the transcript
	// after the separate core-level drain contract is independently tested.
	target:=journal.Target{NodeID:binding.NodeID.String(),ResourceID:leaseResource.String()}
	rateOp:=uuid.NewString()
	_,err=journal.QueueRateMove(ctx,db,entitlement.String(),target,rateOp,0,journal.Rate{Up:40,Down:40})
	if err!=nil {t.Fatal(err)}
	applied,err:=journal.Pending(ctx,db,target)
	if err!=nil {t.Fatal(err)}
	if err:=journal.ConfirmApplied(ctx,db,target,rateOp,1,sha256.Sum256(applied.Payload));err!=nil {
		t.Fatal(err)
	}
	var barrierReply wrapperspb.BytesValue
	barrierNext:="/elx.node.v1.PolicyDelivery/RateBarrierNext"
	if err:=foreign.Invoke(ctx,barrierNext,&emptypb.Empty{},&barrierReply);
		status.Code(err)!=codes.PermissionDenied {
		t.Fatalf("foreign node read pending rate barrier: %v",err)
	}
	if err:=policytransport.ApplyRateBarrier(ctx,good,rateBarrierTestCore{private:key});err!=nil {
		t.Fatalf("authenticated core rate barrier could not finalize: %v",err)
	}
	var committedUp,committedDown int64
	if err:=db.QueryRowContext(ctx,`SELECT committed_up,committed_down
		FROM elx_rate_grants WHERE node_id=$1 AND resource_id=$2`,
		binding.NodeID,leaseResource).Scan(&committedUp,&committedDown);err!=nil {t.Fatal(err)}
	if committedUp!=40 || committedDown!=40 {
		t.Fatalf("signed core barrier did not lower durable commitment: %d/%d",committedUp,committedDown)
	}
	if err:=policytransport.ApplyRateBarrier(ctx,good,rateBarrierTestCore{private:key});
		status.Code(err)!=codes.NotFound {
		t.Fatalf("finalized rate barrier was replayed: %v",err)
	}

	var lease policytransport.Lease
	if err:=json.Unmarshal(leaseWire.Value,&lease);err!=nil {t.Fatal(err)}
	if lease.NodeID!=binding.NodeID || lease.Subscription!=sub ||
		lease.NotAfter-lease.NotBefore!=15 || lease.CeilingUp!=100 || lease.CeilingDown!=100 ||
		!ed25519.Verify(leasePub,
			fmt.Appendf(nil,"elx-control-lease-v2\n%s\n%s\n%d\n%d\n%d\n%d\n%d",
				lease.NodeID,lease.Subscription,lease.Sequence,lease.NotBefore,lease.NotAfter,lease.CeilingUp,lease.CeilingDown),
			lease.Signature) {
		t.Fatalf("Control lease ticket is not node-bound or signature invalid: %+v",lease)
	}
	_,err=db.ExecContext(ctx,`UPDATE elx_entitlements SET enabled=false WHERE id=$1`,entitlement)
	if err!=nil {t.Fatal(err)}
	if err:=good.Invoke(ctx,leaseRoute,wrapperspb.Bytes(leaseInput),&leaseWire);
		status.Code(err)!=codes.FailedPrecondition {
		t.Fatalf("disabled entitlement obtained lease: %v",err)
	}
	_,err=db.ExecContext(ctx,`UPDATE elx_entitlements SET enabled=true WHERE id=$1`,entitlement)
	if err!=nil {t.Fatal(err)}

	goodCore:=&proofCore{key:key,incarnation:binding.Incarnation}
	badCoreKeyPub,badCoreKey,err:=ed25519.GenerateKey(rand.Reader)
	_ = badCoreKeyPub
	if err != nil { t.Fatal(err) }
	badCore:=&proofCore{key:badCoreKey,incarnation:binding.Incarnation}
	if _,err:=PollOne(ctx,foreign,goodCore,binding);status.Code(err)!=codes.InvalidArgument {
		t.Fatalf("foreign node identity not rejected: %v",err)
	}
	if _,err:=PollOne(ctx,good,badCore,binding);status.Code(err)!=codes.PermissionDenied {
		t.Fatalf("untrusted core signed receipt not rejected: %v",err)
	}
	receipt,err:=PollOne(ctx,good,goodCore,binding)
	if err != nil { t.Fatal(err) }
	if !receipt.Crossed || receipt.Sequence!=1 {
		t.Fatalf("signed usage was not counted: %+v",receipt)
	}
	// Replaying signed bytes without a new challenge can never charge again.
	replay,_:=json.Marshal(submitRequest{Binding:binding,Evidence:goodCore.sig})
	var reply wrapperspb.BytesValue
	if err:=good.Invoke(ctx,"/"+serviceName+"/Submit",wrapperspb.Bytes(replay),&reply);status.Code(err)!=codes.FailedPrecondition {
		t.Fatalf("replayed signed bytes were accepted: %v",err)
	}
	var up,down int64
	if err:=db.QueryRowContext(ctx,`SELECT up_bytes,down_bytes FROM elx_usage_periods
		WHERE id=$1`,period).Scan(&up,&down);err!=nil {t.Fatal(err)}
	if up!=40 || down!=70 { t.Fatalf("double count: %d/%d",up,down) }

	// A fence is accepted only for this node + boot + owner generation +
	// VLESS profile. The cryptographic signature is a test fixture; real
	// ElXray must produce it ONLY after denying and draining profile flows.
	device, owner, profile := uuid.New(),uuid.New(),uuid.New()
	_,err=db.ExecContext(ctx,`INSERT INTO elx_devices(id,entitlement_id,key_generation,public_key)
		VALUES($1,$2,1,$3)`,device,entitlement,[]byte(pub))
	if err!=nil {t.Fatal(err)}
	_,err=db.ExecContext(ctx,`INSERT INTO elx_session_owners
		(id,entitlement_id,device_id,node_id,operation_id,generation,key_generation,
		proof_hash,state,core_incarnation,profile_id)
		VALUES($1,$2,$3,$4,$5,1,1,$6,'active',$7,$8)`,
		owner,entitlement,device,binding.NodeID,uuid.New(),make([]byte,32),binding.Incarnation,profile)
	if err!=nil {t.Fatal(err)}
	f:=session.Fence{OwnerID:owner,ProfileID:profile,Generation:1,
		NodeID:binding.NodeID,Incarnation:binding.Incarnation}
	sig:=ed25519.Sign(key,session.FenceTranscript(f))
	if err:=fencetransport.Send(ctx,foreign,f,sig);status.Code(err)!=codes.PermissionDenied {
		t.Fatalf("foreign node released an occupied slot: %v",err)
	}
	wrongProfile:=f
	wrongProfile.ProfileID=uuid.New()
	if err:=fencetransport.Send(ctx,good,wrongProfile,
		ed25519.Sign(key,session.FenceTranscript(wrongProfile)));status.Code(err)!=codes.FailedPrecondition {
		t.Fatalf("correct signature for unrelated VLESS profile released slot: %v",err)
	}
	if err:=fencetransport.Send(ctx,good,f,ed25519.Sign(badCoreKey,
		session.FenceTranscript(f)));status.Code(err)!=codes.PermissionDenied {
		t.Fatalf("untrusted core signature released slot: %v",err)
	}
	if err:=fencetransport.Send(ctx,good,f,sig);status.Code(err)!=codes.FailedPrecondition {
		t.Fatalf("node released slot without Control authorization: %v",err)
	}
	if err:=session.QueueDrain(ctx,db,owner);err!=nil {t.Fatal(err)}
	if err:=fencetransport.ApplyNext(ctx,foreign,fakeProfileDrainer{key});status.Code(err)!=codes.NotFound {
		t.Fatalf("foreign mTLS node received our queued drain job: %v",err)
	}
	if err:=fencetransport.ApplyNext(ctx,good,fakeProfileDrainer{key});err!=nil {
		t.Fatalf("authorized agent did not finish queued profile drain: %v",err)
	}
	// A lost ACK can re-submit the same core receipt without reviving the slot.
	if err:=fencetransport.Send(ctx,good,f,sig);err!=nil {t.Fatal(err)}
	if err:=fencetransport.Send(ctx,good,f,sig);err!=nil {
		t.Fatalf("idempotent fence retry after lost ACK failed: %v",err)
	}
	var state string
	if err:=db.QueryRowContext(ctx,`SELECT state FROM elx_session_owners
		WHERE id=$1`,owner).Scan(&state);err!=nil {t.Fatal(err)}
	if state!="released" {t.Fatalf("verified fence did not release owner: %s",state)}
}
