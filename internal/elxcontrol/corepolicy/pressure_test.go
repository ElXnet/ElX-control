package corepolicy

import (
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
)

func signedPressureFixture(t *testing.T, subscription, nonce string, signer ed25519.PrivateKey) []byte {
	t.Helper()
	data := make([]byte, pressureEvidenceSize)
	boot := uuid.New()
	copy(data[:16], boot[:])
	now := uint64(time.Now().UTC().UnixNano())
	fields := []uint64{
		7, now, 3, 300, 700, // sequence, time, rev, up/down limits
		2048, 9, 1000000000, 2, // upload: payload, waits, nanos, live
		4096, 4, 2000000000, 1, // download
	}
	for i, field := range fields {
		binary.BigEndian.PutUint64(data[16+i*8:24+i*8], field)
	}
	message := fmt.Appendf(nil, "elx-pressure-v1\n%x\n%x\n%x", nonce, subscription, data)
	return append(data, ed25519.Sign(signer, message)...)
}

func TestVerifyPressureEvidenceBindsSourceAndEveryDirection(t *testing.T) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	challenge := "00112233445566778899aabbccddeeff"
	evidence := signedPressureFixture(t, "account", challenge, private)
	sample, err := VerifyPressureEvidence("account", challenge, public, evidence)
	if err != nil {
		t.Fatal(err)
	}
	if sample.Sequence != 7 || sample.Revision != 3 ||
		sample.RateUp != 300 || sample.RateDown != 700 ||
		sample.Upload.PayloadBytes != 2048 || sample.Download.PayloadBytes != 4096 ||
		sample.Upload.BlockedCalls != 9 || sample.Download.BlockedCalls != 4 ||
		sample.Upload.ActiveWaiters != 2 || sample.Download.ActiveWaiters != 1 {
		t.Fatalf("misparsed independent upload/download evidence: %+v", sample)
	}
	if _, err := VerifyPressureEvidence("account", "ffeeddccbbaa99887766554433221100", public, evidence); err == nil {
		t.Fatal("nonce replay was accepted")
	}
	if _, err := VerifyPressureEvidence("another", challenge, public, evidence); err == nil {
		t.Fatal("foreign subscription accepted")
	}
	otherKey, _, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := VerifyPressureEvidence("account", challenge, otherKey, evidence); err == nil {
		t.Fatal("unassigned core key accepted")
	}
	for _, offset := range []int{0, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88, 96, 104, 112, 120} {
		changed := append([]byte(nil), evidence...)
		changed[offset] ^= 1
		if _, err := VerifyPressureEvidence("account", challenge, public, changed); err == nil {
			t.Fatalf("tampered signed byte at offset %d accepted", offset)
		}
	}
	if _, err := VerifyPressureEvidence("account", challenge, public, evidence[:len(evidence)-1]); err == nil {
		t.Fatal("truncated evidence accepted")
	}
}

func TestPressureEvidenceRejectsStaleOrUnboundedFields(t *testing.T) {
	public, private, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	nonce := "00112233445566778899aabbccddeeff"
	for _, tc := range []struct {
		name   string
		offset int
		value  uint64
	}{
		{"stale", 24, uint64(time.Now().Add(-time.Minute).UnixNano())},
		{"future", 24, uint64(time.Now().Add(time.Minute).UnixNano())},
		{"zero revision", 32, 0},
		{"unlimited mismatch", 40, 0},
		{"overlimit", 48, pressureMaxRate + 1},
		{"impossible gauge", 80, 1000001},
		{"negative counter overflow", 56, ^uint64(0)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			data := signedPressureFixture(t, "account", nonce, private)[:pressureEvidenceSize]
			binary.BigEndian.PutUint64(data[tc.offset:tc.offset+8], tc.value)
			m := fmt.Appendf(nil, "elx-pressure-v1\n%x\n%x\n%x", nonce, "account", data)
			evidence := append(data, ed25519.Sign(private, m)...)
			if _, err := VerifyPressureEvidence("account", nonce, public, evidence); err == nil {
				t.Fatal("invalid yet signed pressure sample accepted")
			}
		})
	}
}

func TestValidatePressureProgressRejectsRestartAndRegression(t *testing.T) {
	boot := uuid.New()
	first := PressureSample{
		Incarnation: boot, Sequence: 3, SampledAt: time.Now().Add(-time.Second),
		Revision: 2, Upload: DirectionPressure{PayloadBytes: 100, BlockedCalls: 2, BlockedNanos: 500},
		Download: DirectionPressure{PayloadBytes: 200, BlockedCalls: 3, BlockedNanos: 300},
	}
	next := first
	next.Sequence++
	next.SampledAt = next.SampledAt.Add(time.Second)
	next.Upload.PayloadBytes++
	next.Download.BlockedNanos++
	if err := ValidatePressureProgress(first, next); err != nil {
		t.Fatal(err)
	}
	restarted := next
	restarted.Incarnation = uuid.New()
	if err := ValidatePressureProgress(first, restarted); err != ErrPressureRestart {
		t.Fatalf("core restart bypassed reconciliation: %v", err)
	}
	replay := next
	replay.Sequence = first.Sequence
	if err := ValidatePressureProgress(first, replay); err != ErrPressureRegression {
		t.Fatalf("replayed sequence accepted: %v", err)
	}
	for _, mutate := range []func(*PressureSample){
		func(s *PressureSample) { s.Revision = 1 },
		func(s *PressureSample) { s.Upload.PayloadBytes = 99 },
		func(s *PressureSample) { s.Download.BlockedCalls = 2 },
		func(s *PressureSample) { s.Upload.BlockedNanos = 499 },
	} {
		bad := next
		mutate(&bad)
		if err := ValidatePressureProgress(first, bad); err != ErrPressureRegression {
			t.Fatalf("regressed pressure sample accepted: %v, %+v", err, bad)
		}
	}
}
