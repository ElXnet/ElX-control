package main

import (
	"testing"

	"github.com/google/uuid"
)

func TestParseCollectionRejectsUntrustedOrMalformedAssignments(t *testing.T) {
	ids := []string{uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()}
	valid := []string{
		"-node", ids[0], "-executor", ids[1], "-incarnation", ids[2],
		"-accounting", ids[3], "-period", ids[4], "-generation", "7",
	}
	a, err := parseCollection(valid)
	if err != nil || a.NodeID.String() != ids[0] || a.PeriodID.String() != ids[4] || a.Generation != 7 {
		t.Fatalf("valid assignment rejected: %+v %v", a, err)
	}
	for _, tc := range [][]string{
		nil, {"-node", ids[0]}, append(append([]string{}, valid...), "unexpected"),
		{"-node", uuid.Nil.String(), "-executor", ids[1], "-incarnation", ids[2],
			"-accounting", ids[3], "-period", ids[4], "-generation", "7"},
		{"-node", ids[0], "-executor", ids[1], "-incarnation", ids[2],
			"-accounting", ids[3], "-period", ids[4], "-generation", "0"},
	} {
		if _, err := parseCollection(tc); err == nil {
			t.Fatalf("invalid collector binding accepted: %v", tc)
		}
	}
}
