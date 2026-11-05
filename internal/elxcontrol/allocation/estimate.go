package allocation

import (
	"errors"
	"math/bits"
	"time"

	"github.com/google/uuid"
)

// PressureCounters are cumulative core-signed numbers for ONE direction.
// They measure dispatcher payload and limiter waiting, not wire-rate or
// physical device identities.
type PressureCounters struct {
	PayloadBytes  uint64
	BlockedCalls  uint64
	BlockedNanos  uint64
	ActiveWaiters uint64
}

// PressureSample is the already-verified journal copy of a pinned ElXray
// report. Only the authenticated node accounting path may populate it.
type PressureSample struct {
	Incarnation uuid.UUID
	Sequence    uint64
	SampledAt   time.Time
	Revision    uint64
	Applied     Rates
	Upload      PressureCounters
	Download    PressureCounters
}

type DemandWindow struct {
	Previous PressureSample
	Current  PressureSample
	// Ceiling is the authoritative purchased/FUP upper bound, never the
	// core-reported speed and never an unauthenticated user preference.
	Ceiling Rates
	Now     time.Time
}

var ErrDemandWindow = errors.New("unreliable signed pressure measurement window")

const (
	minDemandWindow = time.Second
	maxDemandWindow = 20 * time.Second
	maxDemandAge    = 10 * time.Second
	minIdleGrant    = 32 << 10 // Keep a live but idle VPN usable.
	demandHeadroom  = 16 << 10 // Additional bytes/s above measured throughput.
)

// EstimateDemand derives requested independent rates from two verified signed
// counter snapshots of the SAME incarnation, policy revision and grant.
//
// Saturated: request up to twice the applied rate, bounded by entitlement.
// Unsaturated: request a 25% headroom over measured payload rate plus 16KiB/s.
// Idle: retain at least a small, strictly positive allocation while sessions
// remain active. A 15% deadband prevents small jitter from moving grants.
//
// This is a pure estimator, not a lease attestation or rate authorization:
// journal.RebalanceDemand still owns the durable budget decision.
func EstimateDemand(w DemandWindow) (Rates, error) {
	a, b := w.Previous, w.Current
	if w.Now.IsZero() || a.Incarnation == uuid.Nil || b.Incarnation != a.Incarnation ||
		a.Sequence == 0 || b.Sequence <= a.Sequence ||
		a.Revision == 0 || b.Revision != a.Revision ||
		a.Applied != b.Applied || !a.Applied.withinBounds() ||
		a.Applied.Up == 0 || a.Applied.Down == 0 ||
		!w.Ceiling.withinBounds() || w.Ceiling.Up == 0 || w.Ceiling.Down == 0 ||
		!b.SampledAt.After(a.SampledAt) ||
		b.SampledAt.After(w.Now.Add(2*time.Second)) ||
		w.Now.Sub(b.SampledAt) > maxDemandAge {
		return Rates{}, ErrDemandWindow
	}
	dt := b.SampledAt.Sub(a.SampledAt)
	if dt < minDemandWindow || dt > maxDemandWindow {
		return Rates{}, ErrDemandWindow
	}
	up, err := directionalDemand(a.Upload, b.Upload, a.Applied.Up, w.Ceiling.Up, dt)
	if err != nil {
		return Rates{}, err
	}
	down, err := directionalDemand(a.Download, b.Download, a.Applied.Down, w.Ceiling.Down, dt)
	if err != nil {
		return Rates{}, err
	}
	return Rates{Up: up, Down: down}, nil
}

func directionalDemand(a, b PressureCounters, applied, ceiling int64, dt time.Duration) (int64, error) {
	if b.PayloadBytes < a.PayloadBytes ||
		b.BlockedCalls < a.BlockedCalls ||
		b.BlockedNanos < a.BlockedNanos ||
		b.ActiveWaiters > 1_000_000 {
		return 0, ErrDemandWindow
	}
	// An observed waiter or any new token-blocking event means the current
	// rate was binding, even if average payload is low (e.g. short burst).
	saturated := b.ActiveWaiters != 0 ||
		b.BlockedCalls > a.BlockedCalls ||
		b.BlockedNanos > a.BlockedNanos
	var requested int64
	if saturated {
		requested = min(ceiling, applied*2)
	} else {
		// Compute exact integer bytes/s without overflowing delta*1e9.
		hi, lo := bits.Mul64(b.PayloadBytes-a.PayloadBytes, uint64(time.Second))
		deltaNanos := uint64(dt)
		if hi >= deltaNanos {
			requested = ceiling
		} else {
			observed, remainder := bits.Div64(hi, lo, deltaNanos)
			if remainder != 0 {
				observed++ // Never round a nonzero demand downward to zero.
			}
			if observed >= uint64(ceiling) {
				requested = ceiling
			} else {
				// applied/ceiling are bounded to 1<<40; arithmetic is safe.
				requested = min(ceiling, int64(observed)+int64(observed)/4+demandHeadroom)
			}
		}
		requested = max(requested, min(ceiling, int64(minIdleGrant)))
	}
	// A lowered FUP or purchased ceiling always wins over deadband.
	if ceiling < applied {
		return min(requested, ceiling), nil
	}
	// +/-15% hysteresis prevents an endless sequence of small reductions
	// and increases after every authenticated 5s sample.
	if requested >= applied-applied*15/100 && requested <= applied+applied*15/100 {
		return applied, nil
	}
	return requested, nil
}
