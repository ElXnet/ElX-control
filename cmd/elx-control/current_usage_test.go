package main

import (
	"testing"

	"github.com/google/uuid"
)

func TestCurrentCollectionRequiresFullTrustedBinding(t *testing.T) {
	ids := []string{uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString(), uuid.NewString()}
	valid := []string{
		"-node", ids[0], "-executor", ids[1], "-incarnation", ids[2],
		"-accounting", ids[3], "-schedule", ids[4], "-generation", "3",
	}
	a, schedule, err := parseCurrentCollection(valid)
	if err != nil || schedule.String() != ids[4] || a.PeriodID != uuid.Nil ||
		a.Generation != 3 || a.NodeID.String() != ids[0] {
		t.Fatalf("valid schedule source rejected: %+v %s: %v", a, schedule, err)
	}
	for _, invalid := range [][]string{
		nil, {"-node", ids[0]},
		append(append([]string{}, valid...), "-period", uuid.NewString()),
		{"-node", ids[0], "-executor", ids[1], "-incarnation", ids[2],
			"-accounting", ids[3], "-schedule", uuid.Nil.String(), "-generation", "3"},
		{"-node", ids[0], "-executor", ids[1], "-incarnation", ids[2],
			"-accounting", ids[3], "-schedule", ids[4], "-generation", "0"},
	} {
		if _, _, err := parseCurrentCollection(invalid); err == nil {
			t.Fatalf("unsafe collection binding accepted: %v", invalid)
		}
	}
}
