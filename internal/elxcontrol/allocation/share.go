// Package allocation calculates target rates before Control reserves grants.
package allocation

import (
	"cmp"
	"errors"
	"slices"

	"github.com/google/uuid"
)

const MaxRate int64 = 1 << 40

type Demand struct {
	DeviceID  uuid.UUID
	Requested int64 // Bytes per second after demand estimation and user cap.
	Weight    int64
}

type Share struct {
	DeviceID uuid.UUID
	Rate     int64
}

// Shares computes weighted max-min targets for one direction. The caller must
// reserve these targets and receive any required barriers before applying them.
func Shares(capacity int64, demands []Demand) ([]Share, error) {
	if capacity < 0 || capacity > MaxRate || len(demands) > 10000 {
		return nil, errors.New("invalid allocation bounds")
	}
	order := slices.Clone(demands)
	seen := make(map[uuid.UUID]bool, len(order))
	var weight int64
	for _, d := range order {
		if d.DeviceID == uuid.Nil || seen[d.DeviceID] || d.Requested < 0 || d.Requested > MaxRate || d.Weight < 1 || d.Weight > 1024 {
			return nil, errors.New("invalid or duplicate device demand")
		}
		seen[d.DeviceID] = true
		weight += d.Weight
	}
	slices.SortFunc(order, func(a, b Demand) int {
		if c := cmp.Compare(a.Requested*b.Weight, b.Requested*a.Weight); c != 0 {
			return c
		}
		return slices.Compare(a.DeviceID[:], b.DeviceID[:])
	})
	out := make([]Share, 0, len(order))
	i := 0
	for i < len(order) {
		d := order[i]
		if d.Requested > capacity*d.Weight/weight {
			break
		}
		out = append(out, Share{d.DeviceID, d.Requested})
		capacity -= d.Requested
		weight -= d.Weight
		i++
	}
	if i == len(order) {
		return out, nil
	}
	type remainder struct {
		index    int
		fraction int64
	}
	remainders := make([]remainder, 0, len(order)-i)
	var used int64
	for _, d := range order[i:] {
		numerator := capacity * d.Weight
		rate := numerator / weight
		remainders = append(remainders, remainder{len(out), numerator % weight})
		out = append(out, Share{d.DeviceID, rate})
		used += rate
	}
	slices.SortStableFunc(remainders, func(a, b remainder) int { return cmp.Compare(b.fraction, a.fraction) })
	for _, r := range remainders[:capacity-used] {
		out[r.index].Rate++
	}
	return out, nil
}
