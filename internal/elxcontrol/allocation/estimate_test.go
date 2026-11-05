package allocation

import (
	"errors"
	"math"
	"testing"
	"time"

	"github.com/google/uuid"
)

func testWindow() DemandWindow {
	now := time.Now().UTC()
	boot := uuid.New()
	return DemandWindow{
		Previous: PressureSample{
			Incarnation: boot, Sequence: 10, Revision: 5,
			SampledAt: now.Add(-6 * time.Second),
			Applied: Rates{Up: 500_000, Down: 500_000},
			Upload: PressureCounters{PayloadBytes: 10_000_000, BlockedCalls: 10, BlockedNanos: 400},
			Download: PressureCounters{PayloadBytes: 20_000_000, BlockedCalls: 20, BlockedNanos: 700},
		},
		Current: PressureSample{
			Incarnation: boot, Sequence: 11, Revision: 5,
			SampledAt: now.Add(-time.Second),
			Applied: Rates{Up: 500_000, Down: 500_000},
			Upload: PressureCounters{PayloadBytes: 10_100_000, BlockedCalls: 10, BlockedNanos: 400},
			Download: PressureCounters{PayloadBytes: 22_500_000, BlockedCalls: 21, BlockedNanos: 900},
		},
		Ceiling: Rates{Up: 2_000_000, Down: 2_000_000},
		Now: now,
	}
}

func TestEstimateDemandDirectionAndSaturation(t *testing.T) {
	w := testWindow()
	got, err := EstimateDemand(w)
	if err != nil {
		t.Fatal(err)
	}
	// Upload moved 100000 bytes in 5s = 20000B/s. 25% headroom
	// plus 16KiB/s => 41384B/s. Download is token-saturated and doubles.
	if got != (Rates{Up: 41_384, Down: 1_000_000}) {
		t.Fatalf("independent saturation miscomputed: %+v", got)
	}
	w.Current.Download.ActiveWaiters = 2
	w.Current.Download.BlockedCalls = w.Previous.Download.BlockedCalls
	w.Current.Download.BlockedNanos = w.Previous.Download.BlockedNanos
	if got, err = EstimateDemand(w); err != nil || got.Down != 1_000_000 {
		t.Fatalf("active waiters did not signal saturation: %+v, %v", got, err)
	}
}

func TestEstimateDemandIdleFloorFUPAndDeadband(t *testing.T) {
	w := testWindow()
	w.Current.Upload = w.Previous.Upload
	w.Current.Download = w.Previous.Download
	got, err := EstimateDemand(w)
	if err != nil || got != (Rates{Up: 32 << 10, Down: 32 << 10}) {
		t.Fatalf("idle VPN should keep small positive grant: %+v %v", got, err)
	}
	// Newly reduced tariff/FUP ceiling always wins, not a stale old rate.
	w.Ceiling = Rates{Up: 8_000, Down: 12_000}
	got, err = EstimateDemand(w)
	if err != nil || got != w.Ceiling {
		t.Fatalf("new FUP limit bypassed: %+v %v", got, err)
	}
	w = testWindow()
	// Select a throughput that implies 500000 B/s after headroom.
	// If within 15%, no small grant-churn operation is proposed.
	w.Current.Upload.PayloadBytes = w.Previous.Upload.PayloadBytes + 1_800_000
	w.Current.Upload.BlockedCalls = w.Previous.Upload.BlockedCalls
	w.Current.Upload.BlockedNanos = w.Previous.Upload.BlockedNanos
	got, err = EstimateDemand(w)
	if err != nil || got.Up != w.Current.Applied.Up {
		t.Fatalf("15%% deadband did not hold current grant: %+v %v", got, err)
	}
}

func TestEstimateDemandRejectsUntrustedOrIncomparableWindows(t *testing.T) {
	base := testWindow()
	tests := map[string]func(*DemandWindow){
		"core restart": func(w *DemandWindow) { w.Current.Incarnation = uuid.New() },
		"replay sequence": func(w *DemandWindow) { w.Current.Sequence = w.Previous.Sequence },
		"older time": func(w *DemandWindow) { w.Current.SampledAt = w.Previous.SampledAt },
		"stale": func(w *DemandWindow) { w.Now = w.Current.SampledAt.Add(30*time.Second) },
		"future": func(w *DemandWindow) { w.Current.SampledAt = w.Now.Add(10*time.Second) },
		"different policy revision": func(w *DemandWindow) { w.Current.Revision++ },
		"changed core rate": func(w *DemandWindow) { w.Current.Applied.Up++ },
		"zero local limit": func(w *DemandWindow) { w.Current.Applied = Rates{}; w.Previous.Applied = Rates{} },
		"no purchase": func(w *DemandWindow) { w.Ceiling.Down = 0 },
		"invalid window": func(w *DemandWindow) { w.Previous.SampledAt = w.Current.SampledAt.Add(-time.Millisecond) },
		"counter rollback": func(w *DemandWindow) { w.Current.Upload.PayloadBytes = 1 },
		"wait rollback": func(w *DemandWindow) { w.Current.Download.BlockedCalls = 1 },
		"negative-equivalent gauge": func(w *DemandWindow) { w.Current.Upload.ActiveWaiters = math.MaxUint64 },
	}
	for label, mutate := range tests {
		t.Run(label,func(t *testing.T){
			window := base
			mutate(&window)
			if _, err := EstimateDemand(window); !errors.Is(err, ErrDemandWindow) {
				t.Fatalf("invalid demand accepted: %v", err)
			}
		})
	}
}

func TestEstimateDemandExtremeCountersNeverOverflowBudget(t *testing.T) {
	w := testWindow()
	w.Previous.Upload.PayloadBytes = 0
	w.Current.Upload.PayloadBytes = math.MaxUint64
	w.Current.Download.ActiveWaiters = 0
	w.Current.Download.BlockedCalls = w.Previous.Download.BlockedCalls
	w.Current.Download.BlockedNanos = w.Previous.Download.BlockedNanos
	got, err := EstimateDemand(w)
	if err != nil {
		t.Fatal(err)
	}
	if got.Up != w.Ceiling.Up || got.Down > w.Ceiling.Down {
		t.Fatalf("huge signed payload escaped bounded rate: %+v", got)
	}
}
