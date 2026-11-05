package allocation

import (
	"errors"
	"slices"

	"github.com/google/uuid"
)

// Rates contains independent upload and download byte-per-second budgets.
// Zero in both directions denotes a disabled local grant, never unlimited.
type Rates struct {
	Up   int64
	Down int64
}

func (r Rates) withinBounds() bool {
	return r.Up >= 0 && r.Up <= MaxRate && r.Down >= 0 && r.Down <= MaxRate
}

// GrantDemand represents a trusted, per-target snapshot from the Control
// journal. Current MUST include the maximum outstanding commitment, not just
// measured throughput. An unknown or pending target is Frozen and cannot
// contribute any reusable capacity until reconciliation/fencing proves release.
type GrantDemand struct {
	TargetID  uuid.UUID
	Current   Rates
	Requested Rates
	Weight    int64
	Frozen    bool
}

type Change struct {
	TargetID uuid.UUID
	From     Rates
	To       Rates
}

// RebalancePlan is a two-phase proposal. Apply all Lower changes, persist the
// signed core barriers and readbacks, and only THEN re-snapshot the durable
// journal before attempting any Raise. Neither a generated plan nor an ACK
// without a core barrier releases an existing commitment.
type RebalancePlan struct {
	Lower             []Change
	Raise             []Change
	Target            map[uuid.UUID]Rates
	FrozenOverBudget  bool
}

// PlanRebalance calculates demand-aware weighted max-min shares independently
// for each direction. Frozen grants retain their commitments, even when idle.
// It deliberately never treats a reported actual throughput as spare budget.
// It is side-effect free: the database journal remains the enforcement gate.
func PlanRebalance(budget Rates, grants []GrantDemand) (RebalancePlan, error) {
	out := RebalancePlan{
		Lower:  []Change{},
		Raise:  []Change{},
		Target: make(map[uuid.UUID]Rates, len(grants)),
	}
	if !budget.withinBounds() || len(grants) > 10000 {
		return out, errors.New("invalid rebalance budget")
	}
	seen := make(map[uuid.UUID]bool, len(grants))
	var frozen Rates
	mutable := make([]GrantDemand, 0, len(grants))
	for _, grant := range grants {
		if grant.TargetID == uuid.Nil || seen[grant.TargetID] ||
			!grant.Current.withinBounds() || !grant.Requested.withinBounds() ||
			grant.Weight < 1 || grant.Weight > 1024 {
			return RebalancePlan{}, errors.New("invalid or duplicate rate grant")
		}
		seen[grant.TargetID] = true
		if grant.Frozen {
			frozen.Up += grant.Current.Up
			frozen.Down += grant.Current.Down
			out.Target[grant.TargetID] = grant.Current
			continue
		}
		mutable = append(mutable, grant)
	}
	if frozen.Up > budget.Up || frozen.Down > budget.Down {
		out.FrozenOverBudget = true
	}
	available := Rates{Up: max(int64(0), budget.Up-frozen.Up),
		Down: max(int64(0), budget.Down-frozen.Down)}
	upDemands := make([]Demand, 0, len(mutable))
	downDemands := make([]Demand, 0, len(mutable))
	for _, grant := range mutable {
		upDemands = append(upDemands, Demand{DeviceID: grant.TargetID,
			Requested: grant.Requested.Up, Weight: grant.Weight})
		downDemands = append(downDemands, Demand{DeviceID: grant.TargetID,
			Requested: grant.Requested.Down, Weight: grant.Weight})
	}
	up, err := Shares(available.Up, upDemands)
	if err != nil {
		return RebalancePlan{}, err
	}
	down, err := Shares(available.Down, downDemands)
	if err != nil {
		return RebalancePlan{}, err
	}
	targets := make(map[uuid.UUID]Rates, len(mutable))
	for _, share := range up {
		v := targets[share.DeviceID]
		v.Up = share.Rate
		targets[share.DeviceID] = v
	}
	for _, share := range down {
		v := targets[share.DeviceID]
		v.Down = share.Rate
		targets[share.DeviceID] = v
	}
	for _, grant := range mutable {
		next := targets[grant.TargetID]
		// Local ElXray policy distinguishes disabled (both zero) from
		// a positive per-direction grant. Never send a partial zero that
		// could be interpreted as unlimited.
		if next.Up == 0 || next.Down == 0 {
			next = Rates{}
		}
		out.Target[grant.TargetID] = next
		floor := Rates{Up: min(grant.Current.Up, next.Up),
			Down: min(grant.Current.Down, next.Down)}
		if floor != grant.Current {
			out.Lower = append(out.Lower, Change{grant.TargetID, grant.Current, floor})
		}
		if floor != next && !out.FrozenOverBudget {
			out.Raise = append(out.Raise, Change{grant.TargetID, floor, next})
		}
	}
	slices.SortFunc(out.Lower, func(a, b Change) int {
		return slices.Compare(a.TargetID[:], b.TargetID[:])
	})
	slices.SortFunc(out.Raise, func(a, b Change) int {
		return slices.Compare(a.TargetID[:], b.TargetID[:])
	})
	return out, nil
}
