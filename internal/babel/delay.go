package babel

import (
	"math"
	"time"
)

type pathDelayQuality struct {
	rttMicros     int64
	jitterMicros  int64
	ageMillis     int64
	confidenceQ16 uint16
}

// DelayStats is a consistent snapshot of the delay estimator for one Babel
// neighbour. VarianceMicros2 is retained instead of only a display jitter so
// independent per-hop variances can be composed mathematically.
type DelayStats struct {
	Mean            time.Duration
	VarianceMicros2 float64
	Min             time.Duration
	Samples         uint32
	OutlierSamples  uint32
	LastSample      time.Time

	minSample  time.Time
	recent     [3]time.Duration
	recentNext uint8
	recentLen  uint8
}

// Jitter returns the exponentially weighted standard deviation of RTT.
func (s DelayStats) Jitter() time.Duration {
	if s.VarianceMicros2 <= 0 || math.IsNaN(s.VarianceMicros2) {
		return 0
	}
	return time.Duration(math.Sqrt(s.VarianceMicros2) * float64(time.Microsecond))
}

// Age returns the elapsed time since the last valid sample.
func (s DelayStats) Age(now time.Time) time.Duration {
	if s.LastSample.IsZero() {
		return 0
	}
	age := now.Sub(s.LastSample)
	if age < 0 {
		return 0
	}
	return age
}

// Confidence combines warm-up progress and freshness into [0,1]. It decays
// linearly after half the maximum sample age instead of dropping abruptly.
func (s DelayStats) Confidence(now time.Time, warmupSamples uint32, maxAge time.Duration) float64 {
	if s.Samples == 0 || maxAge <= 0 {
		return 0
	}
	warmup := 1.0
	if warmupSamples > 0 && s.Samples < warmupSamples {
		warmup = float64(s.Samples) / float64(warmupSamples)
	}
	age := s.Age(now)
	if age >= maxAge {
		return 0
	}
	freshness := 1.0
	if half := maxAge / 2; age > half {
		freshness = float64(maxAge-age) / float64(maxAge-half)
	}
	return warmup * freshness
}

func (s DelayStats) Fresh(now time.Time, warmupSamples uint32, maxAge time.Duration) bool {
	return s.Samples >= warmupSamples && s.Confidence(now, warmupSamples, maxAge) > 0
}

// updated returns the next time-aware exponentially weighted mean and
// variance. The coefficient depends on elapsed time, keeping the filter's
// physical response stable when probes are delayed or lost.
func (s DelayStats) updated(sample time.Duration, now time.Time, tau, minWindow time.Duration) DelayStats {
	if sample < 0 {
		return s
	}
	if s.Samples == 0 || s.LastSample.IsZero() {
		s = DelayStats{
			Mean:       sample,
			Min:        sample,
			Samples:    1,
			LastSample: now,
			minSample:  now,
		}
		s.pushRecent(sample)
		return s
	}

	s.pushRecent(sample)
	filteredSample := sample
	if s.recentLen == uint8(len(s.recent)) {
		values := s.recentOrdered()
		filteredSample = medianDuration(values[0], values[1], values[2])
		// The middle observation can only be classified once the following
		// observation arrives. A 5 ms floor avoids labelling normal timer
		// quantisation as an outlier on very stable links.
		median := filteredSample
		deviation := absDuration(values[1] - median)
		mad := medianDuration(absDuration(values[0]-median), deviation, absDuration(values[2]-median))
		if deviation > max(6*mad, 5*time.Millisecond) {
			s.OutlierSamples++
		}
	}

	dt := now.Sub(s.LastSample)
	if dt <= 0 {
		dt = time.Microsecond
	}
	if tau <= 0 {
		tau = DefaultDelaySmoothingTimeConstant
	}
	alpha := 1 - math.Exp(-float64(dt)/float64(tau))
	if alpha <= 0 {
		alpha = math.SmallestNonzeroFloat64
	} else if alpha > 1 {
		alpha = 1
	}

	// Seed the robust estimator from the first complete window. This removes
	// an isolated second startup sample before the estimate becomes usable.
	if s.Samples == 2 && s.recentLen == uint8(len(s.recent)) {
		values := s.recentOrdered()
		median := medianDuration(values[0], values[1], values[2])
		mad := medianDuration(absDuration(values[0]-median), absDuration(values[1]-median), absDuration(values[2]-median))
		s.Mean = median
		sigmaMicros := 1.4826 * float64(mad) / float64(time.Microsecond)
		s.VarianceMicros2 = sigmaMicros * sigmaMicros
		s.Samples++
		s.LastSample = now
		if s.Min == 0 || sample < s.Min || minWindow <= 0 || now.Sub(s.minSample) >= minWindow {
			s.Min = sample
			s.minSample = now
		}
		return s
	}

	oldMeanMicros := float64(s.Mean) / float64(time.Microsecond)
	sampleMicros := float64(filteredSample) / float64(time.Microsecond)
	delta := sampleMicros - oldMeanMicros
	meanMicros := oldMeanMicros + alpha*delta
	variance := (1 - alpha) * (s.VarianceMicros2 + alpha*delta*delta)
	if variance < 0 || math.IsNaN(variance) {
		variance = 0
	}

	s.Mean = time.Duration(meanMicros * float64(time.Microsecond))
	s.VarianceMicros2 = variance
	s.Samples++
	s.LastSample = now
	if s.Min == 0 || sample < s.Min || minWindow <= 0 || now.Sub(s.minSample) >= minWindow {
		s.Min = sample
		s.minSample = now
	}
	return s
}

func (s *DelayStats) pushRecent(sample time.Duration) {
	s.recent[s.recentNext] = sample
	s.recentNext = (s.recentNext + 1) % uint8(len(s.recent))
	if s.recentLen < uint8(len(s.recent)) {
		s.recentLen++
	}
}

func (s DelayStats) recentOrdered() [3]time.Duration {
	var values [3]time.Duration
	start := s.recentNext
	if s.recentLen < uint8(len(s.recent)) {
		start = 0
	}
	for i := uint8(0); i < s.recentLen; i++ {
		values[i] = s.recent[(start+i)%uint8(len(s.recent))]
	}
	return values
}

func medianDuration(a, b, c time.Duration) time.Duration {
	if a > b {
		a, b = b, a
	}
	if b > c {
		b, c = c, b
	}
	if a > b {
		b = a
	}
	return b
}

func delayStatsPathQuality(s DelayStats, now time.Time, warmup uint32, maxAge time.Duration) pathDelayQuality {
	if s.Samples == 0 {
		return pathDelayQuality{rttMicros: -1, jitterMicros: -1, ageMillis: -1}
	}
	confidence := s.Confidence(now, warmup, maxAge)
	q := math.Round(confidence * float64(math.MaxUint16))
	if q < 0 {
		q = 0
	} else if q > math.MaxUint16 {
		q = math.MaxUint16
	}
	return pathDelayQuality{
		rttMicros:     max(s.Mean.Microseconds(), 0),
		jitterMicros:  max(s.Jitter().Microseconds(), 0),
		ageMillis:     max(s.Age(now).Milliseconds(), 0),
		confidenceQ16: uint16(q),
	}
}

func routePathDelayQuality(r *Route, now time.Time) pathDelayQuality {
	age := r.PathMetricAgeMillis
	if !r.PathMetricsReceivedAt.IsZero() {
		residence := max(now.Sub(r.PathMetricsReceivedAt).Milliseconds(), 0)
		if age >= 0 {
			age += residence
		} else if r.PathRTTMicros >= 0 {
			// Legacy PathMetrics did not carry age; residence time still stops
			// the last received value from remaining fresh forever.
			age = residence
		}
	}
	return pathDelayQuality{
		rttMicros:     r.PathRTTMicros,
		jitterMicros:  r.PathJitterMicros,
		ageMillis:     age,
		confidenceQ16: r.PathMetricConfidence,
	}
}

func composePathDelay(upstream, link pathDelayQuality) pathDelayQuality {
	out := pathDelayQuality{rttMicros: -1, jitterMicros: -1, ageMillis: -1}
	if upstream.rttMicros >= 0 || link.rttMicros >= 0 {
		out.rttMicros = max(upstream.rttMicros, 0) + max(link.rttMicros, 0)
	}
	if upstream.jitterMicros >= 0 && link.jitterMicros >= 0 {
		// Minkowski's inequality makes the sum of standard deviations a safe
		// bound even when hop delays are correlated.
		out.jitterMicros = upstream.jitterMicros + link.jitterMicros
	}
	if upstream.ageMillis >= 0 || link.ageMillis >= 0 {
		out.ageMillis = max(upstream.ageMillis, link.ageMillis)
	}
	if upstream.confidenceQ16 > 0 && link.confidenceQ16 > 0 {
		out.confidenceQ16 = min(upstream.confidenceQ16, link.confidenceQ16)
	}
	return out
}
