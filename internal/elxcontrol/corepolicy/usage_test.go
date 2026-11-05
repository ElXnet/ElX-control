package corepolicy

import (
	"crypto/ed25519"
	"encoding/binary"
	"fmt"
	"testing"
	"time"

	"github.com/google/uuid"
)

func TestVerifyUsageRejectsReplayAndTampering(t *testing.T) {
	key, signer, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatal(err)
	}
	id := uuid.New()
	now := time.Now().UTC()
	data := append([]byte{}, id[:]...)
	data = binary.BigEndian.AppendUint64(data, 9)
	data = binary.BigEndian.AppendUint64(data, uint64(now.UnixNano()))
	data = binary.BigEndian.AppendUint64(data, 123)
	data = binary.BigEndian.AppendUint64(data, 456)
	sig := ed25519.Sign(signer, fmt.Appendf(nil, "elx-usage-v1\n%x\n%x\n%x", "nonce", "lab", data))
	payload := append(data, sig...)
	sample, err := verifyUsage("lab", "nonce", key, payload)
	if err != nil || sample.Incarnation != id || sample.Sequence != 9 || !sample.SampledAt.Equal(now) ||
		sample.UpBytes != 123 || sample.DownBytes != 456 {
		t.Fatalf("unexpected sample: %+v, %v", sample, err)
	}
	if _, err := verifyUsage("lab", "different", key, payload); err == nil {
		t.Fatal("accepted a sample from a previous challenge")
	}
	if _, err := verifyUsage("another", "nonce", key, payload); err == nil {
		t.Fatal("accepted a sample from another subscription")
	}
	payload[47] ^= 1
	if _, err := verifyUsage("lab", "nonce", key, payload); err == nil {
		t.Fatal("accepted an altered payload counter")
	}
}
