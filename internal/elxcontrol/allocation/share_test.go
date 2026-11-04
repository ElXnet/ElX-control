package allocation

import (
	"testing"

	"github.com/google/uuid"
)

func TestSharesSaturationAndWeights(t *testing.T) {
	a, b, c := uuid.New(), uuid.New(), uuid.New()
	out, err := Shares(100, []Demand{{a, 5, 1}, {b, 100, 1}, {c, 100, 2}})
	if err != nil {
		t.Fatal(err)
	}
	got := make(map[uuid.UUID]int64)
	for _, s := range out {
		got[s.DeviceID] = s.Rate
	}
	if got[a] != 5 || got[b] != 32 || got[c] != 63 {
		t.Fatalf("unexpected shares %v", got)
	}
}

func TestSharesRespectCapsAtIntegerBoundaries(t *testing.T) {
	d := []Demand{{uuid.New(), 0, 1}, {uuid.New(), 1, 1024}, {uuid.New(), MaxRate, 17}, {uuid.New(), MaxRate, 1024}}
	for _, capacity := range []int64{0, 1, 2, 15, MaxRate} {
		out, err := Shares(capacity, d)
		if err != nil {
			t.Fatal(err)
		}
		var total int64
		for _, s := range out {
			for _, x := range d {
				if s.DeviceID == x.DeviceID && (s.Rate < 0 || s.Rate > x.Requested) {
					t.Fatalf("share exceeds cap: %+v", s)
				}
			}
			total += s.Rate
		}
		if total != capacity {
			t.Fatalf("sum = %d, want %d", total, capacity)
		}
	}
}

func TestSharesMaximumPopulation(t *testing.T) {
	d := make([]Demand, 10000)
	for i := range d {
		d[i] = Demand{uuid.New(), MaxRate, 1024}
	}
	out, err := Shares(MaxRate, d)
	if err != nil {
		t.Fatal(err)
	}
	var sum int64
	for _, s := range out {
		if s.Rate < MaxRate/10000 || s.Rate > MaxRate/10000+1 {
			t.Fatalf("unfair share: %d", s.Rate)
		}
		sum += s.Rate
	}
	if sum != MaxRate {
		t.Fatalf("sum = %d", sum)
	}
}
