package journal

import (
    "crypto/ed25519"
    "errors"
    "sync"
    "testing"

    "github.com/ElXnet/ElX-control/internal/elxcontrol/session"
    "github.com/google/uuid"
)

// Distinct Ed25519 clients on different nodes race for two durable slots.
// Physical client-to-handshake integration is covered by a separate gate.
func TestTwoDeviceSlotsAcrossNodes(t *testing.T) {
    ctx, db := testDatabase(t)
    db.SetMaxOpenConns(12)
    entitlement := uuid.New()
    _, err := db.ExecContext(ctx, `INSERT INTO elx_entitlements(id,active_slots,valid_until)
        VALUES($1,2,clock_timestamp()+interval '1 hour')`, entitlement)
    checkError(t,err,nil)
    nodes := [2]uuid.UUID{uuid.New(),uuid.New()}
    type core struct { boot uuid.UUID; pub ed25519.PublicKey; priv ed25519.PrivateKey }
    var cores [2]core
    for i := range cores {
        pub,priv,e := ed25519.GenerateKey(nil)
        checkError(t,e,nil)
        cores[i]=core{uuid.New(),pub,priv}
        _,e=db.ExecContext(ctx,`INSERT INTO elx_core_identities(node_id,incarnation,public_key)
            VALUES($1,$2,$3)`,nodes[i],cores[i].boot,[]byte(pub))
        checkError(t,e,nil)
    }
    type client struct {
        a session.Admission
        challenge session.Challenge
        priv ed25519.PrivateKey
    }
    var clients [4]client
    for i := range clients {
        pub,priv,e:=ed25519.GenerateKey(nil)
        checkError(t,e,nil)
        node:=i%2
        a:=session.Admission{EntitlementID:entitlement,DeviceID:uuid.New(),
            NodeID:nodes[node], OperationID:uuid.New(), KeyGeneration:1,
            Incarnation:cores[node].boot, ProfileID:uuid.New(),
            HandshakeHash:[32]byte{1,byte(i+1)},FlowBinding:[32]byte{2,byte(i+1)}}
        _,e=db.ExecContext(ctx,`INSERT INTO elx_devices(id,entitlement_id,key_generation,public_key)
            VALUES($1,$2,1,$3)`,a.DeviceID,entitlement,[]byte(pub))
        checkError(t,e,nil)
        challenge,e:=session.IssueChallenge(ctx,db,a)
        checkError(t,e,nil)
        clients[i]=client{a,challenge,priv}
    }
    claim:=func(i int)(session.Owner,error) {
        c:=clients[i]
        signature:=ed25519.Sign(c.priv,session.ProofTranscript(c.a,c.challenge.Nonce))
        return session.ReserveWithProof(ctx,db,c.a,c.challenge.Nonce,signature)
    }
    type result struct{index int;owner session.Owner;err error}
    race:=func(indices ...int) []result {
        var wg sync.WaitGroup
        ready:=make(chan struct{})
        ch:=make(chan result,len(indices))
        for _,i:=range indices {
            wg.Add(1)
            go func(i int){defer wg.Done(); <-ready; owner,e:=claim(i);ch<-result{i,owner,e}}(i)
        }
        close(ready);wg.Wait();close(ch)
        out:=[]result{}
        for r:=range ch {out=append(out,r)}
        return out
    }
    occupied:=func(expected int){
        t.Helper()
        var n int
        e:=db.QueryRowContext(ctx,`SELECT count(*) FROM elx_session_owners
            WHERE entitlement_id=$1 AND state<>'released'`,entitlement).Scan(&n)
        checkError(t,e,nil)
        if n!=expected{t.Fatalf("occupied slots %d, expected %d",n,expected)}
    }
    owners:=map[int]session.Owner{}
    for _,r:=range race(0,1){checkError(t,r.err,nil);owners[r.index]=r.owner}
    if len(owners)!=2{t.Fatal("two distinct valid devices did not reserve both slots")}
    occupied(2)
    for _,r:=range race(2,3){checkError(t,r.err,session.ErrFull)}
    existing,e:=claim(0)
    checkError(t,e,nil)
    if existing!=owners[0]{t.Fatal("idempotent retry created a new owner")}
    checkError(t,session.QueueDrain(ctx,db,owners[0].ID),nil)
    occupied(2)
    _,e=claim(2);checkError(t,e,session.ErrFull)
    fence:=session.Fence{OwnerID:owners[0].ID,Generation:owners[0].Generation,
        NodeID:nodes[0],Incarnation:cores[0].boot,ProfileID:clients[0].a.ProfileID}
    sig:=ed25519.Sign(cores[0].priv,session.FenceTranscript(fence))
    foreign:=ed25519.Sign(cores[1].priv,session.FenceTranscript(fence))
    checkError(t,session.ReleaseAfterFence(ctx,db,fence,cores[1].pub,foreign),session.ErrFence)
    wrong:=fence;wrong.Generation++
    checkError(t,session.ReleaseAfterFence(ctx,db,wrong,cores[0].pub,
        ed25519.Sign(cores[0].priv,session.FenceTranscript(wrong))),session.ErrFence)
    occupied(2)
    checkError(t,session.ReleaseAfterFence(ctx,db,fence,cores[0].pub,sig),nil)
    occupied(1)
    wins:=0
    for _,r:=range race(2,3) {
        if r.err==nil {wins++} else if !errors.Is(r.err,session.ErrFull){t.Fatal(r.err)}
    }
    if wins!=1{t.Fatalf("one freed slot admitted %d clients",wins)}
    occupied(2)
    checkError(t,session.ReleaseAfterFence(ctx,db,fence,cores[0].pub,sig),nil)
    occupied(2)
    old,e:=claim(0)
    checkError(t,e,nil)
    if old.State!="released"||old.ID!=owners[0].ID{t.Fatalf("old owner revived: %+v",old)}
}
