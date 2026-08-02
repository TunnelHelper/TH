package babel

import (
	"math"
	"testing"
	"time"
)

func TestDelayStatsTimeAwareMeanVarianceAndFreshness(t *testing.T) {
	t0 := time.Now()
	stats := DelayStats{}.updated(10*time.Millisecond, t0, time.Second, time.Minute)
	stats = stats.updated(20*time.Millisecond, t0.Add(time.Second), time.Second, time.Minute)
	alpha := 1 - math.Exp(-1)
	wantMeanMicros := 10_000 + alpha*10_000
	if delta := math.Abs(float64(stats.Mean.Microseconds()) - wantMeanMicros); delta > 1 {
		t.Fatalf("mean = %dus, want %.1fus", stats.Mean.Microseconds(), wantMeanMicros)
	}
	wantVariance := (1 - alpha) * alpha * 10_000 * 10_000
	if delta := math.Abs(stats.VarianceMicros2-wantVariance) / wantVariance; delta > 1e-9 {
		t.Fatalf("variance = %g, want %g", stats.VarianceMicros2, wantVariance)
	}
	if stats.Confidence(t0.Add(time.Second), 4, 10*time.Second) != 0.5 {
		t.Fatalf("two of four warm-up samples must have 0.5 confidence")
	}
	if stats.Fresh(t0.Add(time.Second), 4, 10*time.Second) {
		t.Fatal("estimator must not be fresh before warm-up completes")
	}
	stats.Samples = 4
	if !stats.Fresh(t0.Add(6*time.Second), 4, 10*time.Second) {
		t.Fatal("warmed estimator before max age must be fresh")
	}
	if got := stats.Confidence(t0.Add(11*time.Second), 4, 10*time.Second); got != 0 {
		t.Fatalf("expired confidence = %g, want 0", got)
	}
}

func TestComposePathDelayUsesConservativeJitterBound(t *testing.T) {
	upstream := pathDelayQuality{rttMicros: 10_000, jitterMicros: 2_000, ageMillis: 300, confidenceQ16: 60_000}
	link := pathDelayQuality{rttMicros: 5_000, jitterMicros: 1_000, ageMillis: 100, confidenceQ16: 50_000}
	got := composePathDelay(upstream, link)
	if got.rttMicros != 15_000 || got.jitterMicros != 3_000 || got.ageMillis != 300 || got.confidenceQ16 != 50_000 {
		t.Fatalf("composed quality = %+v", got)
	}
}

func TestUnknownDelayDoesNotBecomeZeroLatency(t *testing.T) {
	unknown := delayStatsPathQuality(DelayStats{}, time.Now(), 4, 10*time.Second)
	if unknown.rttMicros != -1 || unknown.jitterMicros != -1 || unknown.ageMillis != -1 {
		t.Fatalf("empty estimator quality = %+v, want unknown values", unknown)
	}
	got := composePathDelay(pathDelayQuality{rttMicros: -1, jitterMicros: -1, ageMillis: -1}, unknown)
	if got.rttMicros != -1 || got.jitterMicros != -1 || got.ageMillis != -1 {
		t.Fatalf("unknown path composition = %+v, want unknown values", got)
	}
}

func TestDelayStatsRejectsIsolatedSpikeAndAcceptsSustainedStep(t *testing.T) {
	t0 := time.Now()
	stats := DelayStats{}
	for i, sample := range []time.Duration{10, 10, 200, 10} {
		stats = stats.updated(sample*time.Millisecond, t0.Add(time.Duration(i)*time.Second), 30*time.Second, time.Minute)
	}
	if stats.Mean > 11*time.Millisecond {
		t.Fatalf("isolated spike polluted mean: %s", stats.Mean)
	}
	if stats.OutlierSamples != 1 {
		t.Fatalf("outlier samples = %d, want 1", stats.OutlierSamples)
	}

	stats = stats.updated(100*time.Millisecond, t0.Add(4*time.Second), 30*time.Second, time.Minute)
	before := stats.Mean
	stats = stats.updated(100*time.Millisecond, t0.Add(5*time.Second), 30*time.Second, time.Minute)
	if stats.Mean <= before {
		t.Fatalf("sustained step did not enter estimator: before=%s after=%s", before, stats.Mean)
	}
}

func TestDelayPublicationUsesDeadbandIntervalAndFreshness(t *testing.T) {
	speaker := newTestSpeaker(t)
	neighbour := newFakeNeighbour(speaker, "fe80::1", 96)
	t0 := time.Now()
	for i := 0; i < 4; i++ {
		neighbour.recordDelaySample(10*time.Millisecond, t0.Add(time.Duration(i)*time.Second))
	}
	first := t0.Add(3 * time.Second)
	if !neighbour.shouldPublishDelay(first) {
		t.Fatal("first warmed estimate must publish")
	}
	neighbour.recordDelaySample(20*time.Millisecond, first.Add(time.Second))
	if neighbour.shouldPublishDelay(first.Add(time.Second)) {
		t.Fatal("significant change inside minimum interval must not publish")
	}
	neighbour.recordDelaySample(20*time.Millisecond, first.Add(2*time.Second))
	if !neighbour.shouldPublishDelay(first.Add(5 * time.Second)) {
		t.Fatal("confirmed significant estimate after minimum interval must publish")
	}
	if !neighbour.shouldPublishDelay(first.Add(16 * time.Second)) {
		t.Fatal("freshness decay must publish even without another sample")
	}
}
