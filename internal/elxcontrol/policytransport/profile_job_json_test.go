package policytransport

import (
	"testing"
)

func TestTechnicalJobJSONUniqueMembers(t *testing.T) {
	for _, raw := range []string{
		`{"Grant":{"ProfileID":"a"},"Signature":"ok"}`,
		`{"Grant":{"ProfileID":"a","profileid":"b"},"Signature":"ok"}`,
		`{"Grant":{},"Grant":{},"Signature":"ok"}`,
		`{"Grant":{},"grant":{},"Signature":"ok"}`,
		`{"Grant":{},"Signature":"ok","signature":"other"}`,
		`{"Grant":{}}{"Signature":"other"}`,
	} {
		err := validateUniqueControlJobJSON([]byte(raw))
		if raw == `{"Grant":{"ProfileID":"a"},"Signature":"ok"}` {
			if err != nil {
				t.Fatalf("valid technical job JSON rejected: %v", err)
			}
		} else if err == nil {
			t.Fatalf("ambiguous technical job JSON accepted: %s", raw)
		}
	}
}
