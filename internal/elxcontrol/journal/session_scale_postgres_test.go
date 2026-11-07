package journal

import (
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"fmt"
	"sync"
	"testing"
	"time"

	"github.com/ElXnet/ElX-control/internal/elxcontrol/session"
	"github.com/google/uuid"
)

// This is a 200-owner PostgreSQL concurrency/authorization stress gate,
// not a claim that 200 physical VPN clients or 200 Mbps streams were tested.
// Every reservation uses an independent Ed25519 key and challenge and three
// separately pinned Control node identities.
func TestSessionLedger200ProofBoundDevicesAcrossThreeNodes(t *testing.T) {
	_, db := testDatabase(t)
	ctx, cancel := context.WithTimeout(context.Background(), 110*time.Second)
	defer cancel()
	db.SetMaxOpenConns(24)
	entitlement := uuid.New()
	_, err := db.ExecContext(ctx, `INSERT INTO elx_entitlements(id,active_slots,valid_until)
		VALUES($1,200,clock_timestamp()+interval '1 hour')`,entitlement)
	checkError(t,err,nil)

	type pinnedCore struct{node,boot uuid.UUID}
	cores := [3]pinnedCore{}
	for i:=range cores {
		pub,_,genErr:=ed25519.GenerateKey(nil)
		checkError(t,genErr,nil)
		cores[i]=pinnedCore{uuid.New(),uuid.New()}
		_,err=db.ExecContext(ctx,`INSERT INTO elx_core_identities(node_id,incarnation,public_key)
			VALUES($1,$2,$3)`,cores[i].node,cores[i].boot,[]byte(pub))
		checkError(t,err,nil)
	}

	type candidate struct{
		admission session.Admission
		key ed25519.PrivateKey
	}
	const slots=200
	const extra=10
	candidates:=make([]candidate,slots+extra)
	for i:=range candidates{
		public,private,genErr:=ed25519.GenerateKey(nil)
		checkError(t,genErr,nil)
		node:=cores[i%len(cores)]
		h:=sha256.Sum256([]byte(fmt.Sprintf("test-only-handshake-%d",i)))
		b:=sha256.Sum256([]byte(fmt.Sprintf("test-only-channel-%d",i)))
		a:=session.Admission{
			EntitlementID:entitlement,DeviceID:uuid.New(),NodeID:node.node,
			OperationID:uuid.New(),KeyGeneration:1,Incarnation:node.boot,
			ProfileID:uuid.New(),HandshakeHash:h,FlowBinding:b,
		}
		_,err=db.ExecContext(ctx,`INSERT INTO elx_devices
			(id,entitlement_id,key_generation,public_key)
			VALUES($1,$2,1,$3)`,a.DeviceID,entitlement,[]byte(public))
		checkError(t,err,nil)
		candidates[i]=candidate{a,private}
	}

	// A short challenge expiry is intentional in production. Provision each
	// batch immediately before racing it, rather than issuing 210 nonces
	// and allowing the later half to expire during test setup.
	reserveBatch:=func(first,last int,expectFull bool) {
		t.Helper()
		type claim struct{
			c candidate
			nonce [32]byte
		}
		claims:=make([]claim,last-first)
		for i:=first;i<last;i++ {
			nonce,issueErr:=session.IssueChallenge(ctx,db,candidates[i].admission)
			checkError(t,issueErr,nil)
			claims[i-first]=claim{candidates[i],nonce.Nonce}
		}
		start:=make(chan struct{})
		sem:=make(chan struct{},12)
		results:=make(chan error,len(claims))
		var wg sync.WaitGroup
		for _,req:=range claims{
			req:=req
			wg.Add(1)
			go func(){
				defer wg.Done()
				<-start
				sem<-struct{}{}
				defer func(){<-sem}()
				signature:=ed25519.Sign(req.c.key,
					session.ProofTranscript(req.c.admission,req.nonce))
				_,reserveErr:=session.ReserveWithProof(ctx,db,
					req.c.admission,req.nonce,signature)
				results<-reserveErr
			}()
		}
		close(start)
		wg.Wait()
		close(results)
		for reserveErr:=range results{
			if expectFull {
				if !errors.Is(reserveErr,session.ErrFull) {
					t.Fatalf("201st+ device was not denied when all slots occupied: %v",reserveErr)
				}
			} else if reserveErr!=nil {
				t.Fatalf("valid signed device denied or raced: %v",reserveErr)
			}
		}
	}
	for first:=0;first<slots;first+=40{
		reserveBatch(first,first+40,false)
	}
	var occupied int
	checkError(t,db.QueryRowContext(ctx,`SELECT count(*)
		FROM elx_session_owners WHERE entitlement_id=$1
		AND state<>'released'`,entitlement).Scan(&occupied),nil)
	if occupied!=slots{
		t.Fatalf("expected %d occupied signed device slots, got %d",slots,occupied)
	}
	reserveBatch(slots,slots+extra,true)
	checkError(t,db.QueryRowContext(ctx,`SELECT count(*)
		FROM elx_session_owners WHERE entitlement_id=$1
		AND state<>'released'`,entitlement).Scan(&occupied),nil)
	if occupied!=slots{
		t.Fatalf("capacity violation under contention: %d owners",occupied)
	}
	// A copied device proof cannot be turned into a 201st device by simply
	// changing the ID: the Ed25519 key must match the enrolled device key.
	probe:=candidates[slots]
	challenge,err:=session.IssueChallenge(ctx,db,probe.admission)
	checkError(t,err,nil)
	foreign:=candidates[0].key
	_,err=session.ReserveWithProof(ctx,db,probe.admission,challenge.Nonce,
		ed25519.Sign(foreign,session.ProofTranscript(probe.admission,challenge.Nonce)))
	if !errors.Is(err,session.ErrProof){
		t.Fatalf("wrong registered device signing key was accepted: %v",err)
	}
}
