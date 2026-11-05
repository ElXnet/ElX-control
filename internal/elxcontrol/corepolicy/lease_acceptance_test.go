package corepolicy

import (
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
)

func makeLeaseAcceptance(signer ed25519.PrivateKey, nonce, subscription string,
	boot, node uuid.UUID, values [7]uint64) []byte {
	raw:=make([]byte,leaseAcceptanceSize)
	copy(raw[:16],boot[:])
	copy(raw[16:32],node[:])
	for i,v:=range values{
		binary.BigEndian.PutUint64(raw[32+i*8:40+i*8],v)
	}
	message:=fmt.Appendf(nil,"elx-lease-accept-v1\n%x\n%x\n%x",nonce,subscription,raw)
	return append(raw,ed25519.Sign(signer,message)...)
}

func TestCoreLeaseEvidenceRejectsForgeriesAndExpiredTickets(t *testing.T) {
	key,private,err:=ed25519.GenerateKey(nil)
	if err!=nil {t.Fatal(err)}
	node,boot:=uuid.New(),uuid.New()
	now:=time.Now().UTC().Truncate(time.Second)
	nonce:="00112233445566778899aabbccddeeff"
	values:=[7]uint64{17,uint64(now.Add(15*time.Second).Unix()),100,200,3,80,190}
	payload:=makeLeaseAcceptance(private,nonce,"account",boot,node,values)
	lease,err:=VerifyLeaseAcceptance("account",nonce,key,payload,now)
	if err!=nil {t.Fatal(err)}
	if lease.NodeID!=node || lease.Incarnation!=boot ||
		lease.Sequence!=17 || lease.CeilingUp!=100 || lease.AppliedDown!=190 ||
		lease.Revision!=3 || !lease.ExpiresAt.Equal(now.Add(15*time.Second)) {
		t.Fatalf("wrong verified lease: %+v",lease)
	}
	if err:=ValidateAcceptedLeaseBinding(lease,node,boot,3,80,190,now);err!=nil{
		t.Fatalf("valid active lease rejected: %v",err)
	}
	for label,mutate:=range map[string]func(a *AcceptedLease){
		"wrong node":func(a *AcceptedLease){a.NodeID=uuid.New()},
		"wrong core":func(a *AcceptedLease){a.Incarnation=uuid.New()},
		"stale policy":func(a *AcceptedLease){a.Revision=2},
		"stale applied rate":func(a *AcceptedLease){a.AppliedDown=191},
		"weak ceiling":func(a *AcceptedLease){a.CeilingUp=79},
	}{
		t.Run(label,func(t *testing.T){
			bad:=lease
			mutate(&bad)
			if err:=ValidateAcceptedLeaseBinding(bad,node,boot,3,80,190,now);err==nil{
				t.Fatalf("unbound core acceptance: %+v",bad)
			}
		})
	}
	if _,err:=VerifyLeaseAcceptance("account",
		"ffeeddccbbaa99887766554433221100",key,payload,now);err==nil{
		t.Fatal("old nonce replay accepted")
	}
	if _,err:=VerifyLeaseAcceptance("unrelated",nonce,key,payload,now);err==nil{
		t.Fatal("another subscription accepted")
	}
	foreign,_,err:=ed25519.GenerateKey(nil)
	if err!=nil {t.Fatal(err)}
	if _,err:=VerifyLeaseAcceptance("account",nonce,foreign,payload,now);err==nil{
		t.Fatal("another core signing key accepted")
	}
	for _,offset:=range []int{0,15,16,31,32,40,48,56,64,72,80,88}{
		changed:=append([]byte(nil),payload...)
		changed[offset]^=1
		if _,err:=VerifyLeaseAcceptance("account",nonce,key,changed,now);err==nil{
			t.Fatalf("tampered signed lease field %d accepted",offset)
		}
	}
	for label,alter:=range map[string]func(v *[7]uint64){
		"expired":func(v *[7]uint64){v[1]=uint64(now.Add(-time.Second).Unix())},
		"near expiry":func(v *[7]uint64){v[1]=uint64(now.Add(time.Second).Unix())},
		"unbounded expiry":func(v *[7]uint64){v[1]=uint64(now.Add(time.Minute).Unix())},
		"zero sequence":func(v *[7]uint64){v[0]=0},
		"zero ceiling":func(v *[7]uint64){v[2]=0},
		"rate beyond ceiling":func(v *[7]uint64){v[5]=101},
		"unlimited":func(v *[7]uint64){v[6]=0},
		"invalid revision":func(v *[7]uint64){v[4]=0},
	}{
		t.Run(label,func(t *testing.T){
			testValues:=values
			alter(&testValues)
			signed:=makeLeaseAcceptance(private,nonce,"account",boot,node,testValues)
			if _,err:=VerifyLeaseAcceptance("account",nonce,key,signed,now);err==nil{
				t.Fatalf("invalid but correctly signed lease accepted: %+v",testValues)
			}
		})
	}
}
