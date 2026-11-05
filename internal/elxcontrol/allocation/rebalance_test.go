package allocation

import (
	"testing"

	"github.com/google/uuid"
)

func TestPlanRebalanceDemandAndIndependentDirections(t *testing.T) {
	a, b, c := uuid.New(), uuid.New(), uuid.New()
	plan, err := PlanRebalance(Rates{100, 100}, []GrantDemand{
		{DeviceID: a, Current: Rates{50, 50}, Requested: Rates{5, 100}, Weight: 1},
		{DeviceID: b, Current: Rates{50, 50}, Requested: Rates{100, 100}, Weight: 1},
		{DeviceID: c, Current: Rates{}, Requested: Rates{100, 5}, Weight: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	// Upload demand: 5 + 47 + 48; download demand: 47 + 48 + 5.
	// Remainders are deterministic by UUID; assert the saturation and totals.
	if plan.Target[a].Up != 5 || plan.Target[c].Down != 5 {
		t.Fatalf("small demand did not return spare capacity: %+v", plan.Target)
	}
	var totalUp, totalDown int64
	for _, rate := range plan.Target {
		totalUp += rate.Up
		totalDown += rate.Down
	}
	if totalUp != 100 || totalDown != 100 {
		t.Fatalf("directional budgets exceeded or left unused: up=%d down=%d", totalUp, totalDown)
	}
	if len(plan.Lower) == 0 || len(plan.Raise) == 0 {
		t.Fatalf("expected reduce-before-increase phases: %+v", plan)
	}
	for _, change := range plan.Lower {
		if change.To.Up > change.From.Up || change.To.Down > change.From.Down {
			t.Fatalf("increase scheduled before barriers: %+v", change)
		}
	}
	for _, change := range plan.Raise {
		if change.To.Up < change.From.Up || change.To.Down < change.From.Down {
			t.Fatalf("decrease scheduled in increase phase: %+v", change)
		}
	}
}

func TestPlanRebalanceFrozenUnknownNeverReusesBudget(t *testing.T) {
	unknown, active := uuid.New(), uuid.New()
	plan, err := PlanRebalance(Rates{100, 100}, []GrantDemand{
		{DeviceID: unknown, Current: Rates{70, 40}, Requested: Rates{}, Weight: 1, Frozen: true},
		{DeviceID: active, Current: Rates{30, 60}, Requested: Rates{100, 100}, Weight: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	if plan.Target[unknown] != (Rates{70, 40}) || plan.Target[active] != (Rates{30, 60}) {
		t.Fatalf("frozen node's rate incorrectly reused: %+v", plan.Target)
	}
	if len(plan.Raise) != 0 || len(plan.Lower) != 0 || plan.FrozenOverBudget {
		t.Fatalf("unexpected changes with fully committed budget: %+v", plan)
	}
}

func TestPlanRebalanceFrozenOverBudgetNeverRaises(t *testing.T) {
	frozen, live := uuid.New(), uuid.New()
	plan, err := PlanRebalance(Rates{40, 40}, []GrantDemand{
		{DeviceID: frozen, Current: Rates{50, 50}, Requested: Rates{}, Weight: 1, Frozen: true},
		{DeviceID: live, Current: Rates{10, 10}, Requested: Rates{40, 40}, Weight: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !plan.FrozenOverBudget || len(plan.Raise) != 0 {
		t.Fatalf("inconsistent frozen state granted additional rate: %+v", plan)
	}
	if len(plan.Lower) != 1 || plan.Lower[0].To != (Rates{}) {
		t.Fatalf("expected drain of mutable grant: %+v", plan.Lower)
	}
	if plan.Target[frozen] != (Rates{50, 50}) {
		t.Fatalf("frozen commitment was erased: %+v", plan.Target)
	}
}

func TestPlanRebalanceDoesNotSendPartialZero(t *testing.T) {
	a, b := uuid.New(), uuid.New()
	plan, err := PlanRebalance(Rates{1, 100}, []GrantDemand{
		{DeviceID: a, Current: Rates{1, 50}, Requested: Rates{100, 100}, Weight: 1},
		{DeviceID: b, Current: Rates{}, Requested: Rates{100, 100}, Weight: 1},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range plan.Target {
		if (r.Up == 0) != (r.Down == 0) {
			t.Fatalf("partial zero could trigger unlimited direction: %+v", plan.Target)
		}
	}
}

func TestPlanRebalanceRejectsInvalidAndDuplicateInputs(t *testing.T) {
	id := uuid.New()
	cases := []struct {
		budget Rates
		input []GrantDemand
	}{
		{Rates{-1, 100}, nil},
		{Rates{100, 100}, []GrantDemand{{DeviceID: uuid.Nil, Weight: 1}}},
		{Rates{100, 100}, []GrantDemand{{DeviceID: id, Weight: 0}}},
		{Rates{100, 100}, []GrantDemand{{DeviceID: id, Weight: 1, Current: Rates{-1, 2}}}},
		{Rates{100, 100}, []GrantDemand{{DeviceID: id, Weight: 1}, {DeviceID: id, Weight: 1}}},
	}
	for i, tc := range cases {
		if _, err := PlanRebalance(tc.budget, tc.input); err == nil {
			t.Errorf("case %d unexpectedly accepted", i)
		}
	}
}

func TestPlanRebalanceDeterministicAcrossInputOrder(t *testing.T) {
	a, b, c := uuid.New(), uuid.New(), uuid.New()
	input := []GrantDemand{
		{DeviceID: a, Current: Rates{30, 30}, Requested: Rates{100, 100}, Weight: 1},
		{DeviceID: b, Current: Rates{30, 30}, Requested: Rates{100, 100}, Weight: 1},
		{DeviceID: c, Current: Rates{30, 30}, Requested: Rates{100, 100}, Weight: 1},
	}
	first, err := PlanRebalance(Rates{100, 100}, input)
	if err != nil {
		t.Fatal(err)
	}
	input[0], input[2] = input[2], input[0]
	second, err := PlanRebalance(Rates{100, 100}, input)
	if err != nil {
		t.Fatal(err)
	}
	for id, rate := range first.Target {
		if second.Target[id] != rate {
			t.Fatalf("input iteration order changed allocation for %s: %+v vs %+v", id, first.Target, second.Target)
		}
	}
}
