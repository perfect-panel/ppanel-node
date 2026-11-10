package congestion

import "testing"

func TestBandwidthSamplerUsesBoundedInitialRings(t *testing.T) {
	sampler := newBandwidthSampler(10)
	if defaultConnectionStateMapQueueSize != 64 || defaultCandidatesBufferSize != 64 {
		t.Fatal("unexpected BBR initial queue constants")
	}
	stateCapacity := len(sampler.connectionStateMap.entries.ring)
	if stateCapacity != defaultConnectionStateMapQueueSize {
		t.Fatalf("connection state capacity = %d", stateCapacity)
	}
	candidateCapacity := len(sampler.a0Candidates.ring)
	if candidateCapacity != defaultCandidatesBufferSize {
		t.Fatalf("candidate capacity = %d", candidateCapacity)
	}
}

func TestRingBufferGrowsPastInitialCapacity(t *testing.T) {
	var ring RingBuffer[int]
	ring.Init(2)
	for value := range 5 {
		ring.PushBack(value)
	}
	if ring.Len() != 5 || len(ring.ring) < 5 {
		t.Fatalf("ring length=%d capacity=%d", ring.Len(), len(ring.ring))
	}
	for value := range 5 {
		if got := ring.PopFront(); got != value {
			t.Fatalf("value %d = %d", value, got)
		}
	}
}
