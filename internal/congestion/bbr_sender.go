package congestion

import (
	"fmt"
	"os"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
	"github.com/quic-go/quic-go/qlogwriter"
)

// bbrSender is a BBRv1 congestion controller (Cardwell et al., "BBR:
// Congestion-Based Congestion Control"). It implements the same SendAlgorithm
// interface as cubicSender so it is a drop-in replacement selected via
// Config.CongestionControl. Constants match the paper (cross-checked against the
// repo's verified pkg/cc/bbr): startup gain 2/ln2, drain 1/that, PROBE_BW pacing
// cycle [1.25,0.75,1×6] with cwnd_gain 2, startup exit when BtlBw grows <25% for
// 3 rounds, PROBE_RTT every 10s holding cwnd=4·MTU for 200ms.
//
// Why BBR for the XNC/CellFusion baseline: it is rate-based, NOT loss-based, so a
// wireless burst (heavy loss, unchanged RTT) does NOT collapse the send rate the
// way Cubic does — which is exactly why CellFusion §4.2 specifies BBR.

const (
	bbrHighGain      = 2.885 // 2/ln2: startup pacing & cwnd gain
	bbrDrainGain     = 1.0 / bbrHighGain
	bbrCwndGainProbe = 2.0
	bbrFullBwThresh  = 1.25 // BtlBw must grow >=25%/round to stay in Startup
	bbrFullBwCnt     = 3
	bbrProbeRTTDur   = 200 * time.Millisecond
	bbrProbeRTTIvl   = 10 * time.Second
	bbrBwFilterLen   = 10 // BtlBw max-filter window, in rounds
	bbrMinPipePkts   = 4
)

var bbrProbeBWGains = [8]float64{1.25, 0.75, 1, 1, 1, 1, 1, 1}

type bbrMode int

const (
	bbrStartup bbrMode = iota
	bbrDrain
	bbrProbeBW
	bbrProbeRTT
)

// bwSample is one (round, bits/s) delivery-rate sample for the windowed max.
type bwSample struct {
	round uint64
	bw    float64
}

type bbrSentState struct {
	sentTime  monotime.Time
	delivered protocol.ByteCount // cumulative delivered at send time
}

type bbrSender struct {
	rttStats  *utils.RTTStats
	connStats *utils.ConnectionStats
	clock     Clock
	pacer     *pacer

	maxDatagramSize protocol.ByteCount

	mode       bbrMode
	pacingGain float64
	cwndGain   float64
	cwnd       protocol.ByteCount

	btlBw   float64 // bits/s (windowed max of delivery rate)
	bwWin   []bwSample
	rtProp  time.Duration

	// round accounting: a round completes when a packet sent at/after roundStartPN acks
	roundCount   uint64
	roundStartPN protocol.PacketNumber
	largestSent  protocol.PacketNumber

	// startup-exit detection
	fullBw        float64
	fullBwCount   int
	fullBwReached bool

	// PROBE_BW gain cycling
	cycleIndex int
	cycleStamp monotime.Time

	// PROBE_RTT
	priorMode     bbrMode
	probeRTTStamp monotime.Time // when RTprop was last refreshed
	probeRTTStart monotime.Time

	delivered protocol.ByteCount // cumulative acked bytes
	inflight  protocol.ByteCount // bytes sent but not yet acked/lost (for DRAIN exit + cycle gating)
	sent      map[protocol.PacketNumber]bbrSentState

	// app-limited detection (mirrors the verified pkg/cc/bbr): lastBlocked is the
	// last time we were REJECTED by cwnd or pacing (network is the limiter). If no
	// such rejection happened within ~1 RTprop, the application — not the network —
	// is the bottleneck, and its low (loss-reduced) delivery-rate samples must NOT
	// be fed into the BtlBw max-filter. Without this, an app-limited flow under loss
	// spirals: the loss-reduced sample lowers BtlBw, the pacer throttles, less is
	// sent, the next sample is lower still — collapsing cwnd to the 4·MTU floor.
	lastBlocked monotime.Time
	appLimited  bool

	started bool

	debug   bool          // QUIC_BBR_DEBUG=1: time-throttled state dump to stderr
	lastDbg monotime.Time
}

var (
	_ SendAlgorithm               = &bbrSender{}
	_ SendAlgorithmWithDebugInfos = &bbrSender{}
)

// NewBBRSender builds a BBRv1 sender wired to quic-go's pacer/RTT scaffolding.
func NewBBRSender(
	clock Clock,
	rttStats *utils.RTTStats,
	connStats *utils.ConnectionStats,
	initialMaxDatagramSize protocol.ByteCount,
	qlogger qlogwriter.Recorder,
) *bbrSender {
	b := &bbrSender{
		rttStats:        rttStats,
		connStats:       connStats,
		clock:           clock,
		maxDatagramSize: initialMaxDatagramSize,
		mode:            bbrStartup,
		pacingGain:      bbrHighGain,
		cwndGain:        bbrHighGain,
		cwnd:            initialCongestionWindow * initialMaxDatagramSize,
		sent:            make(map[protocol.PacketNumber]bbrSentState),
		roundStartPN:    protocol.InvalidPacketNumber,
		largestSent:     protocol.InvalidPacketNumber,
		debug:           os.Getenv("QUIC_BBR_DEBUG") == "1",
	}
	b.pacer = newPacer(b.bandwidthForPacer)
	return b
}

// bandwidthForPacer is the rate the token-bucket pacer uses: pacing_gain · BtlBw.
// Before the first BtlBw sample it falls back to cwnd/RTT so startup can ramp.
func (b *bbrSender) bandwidthForPacer() Bandwidth {
	bw := b.btlBw
	if bw <= 0 {
		// seed: initial cwnd over a nominal RTT so the pacer isn't stalled at t=0
		rtt := b.rtProp
		if rtt <= 0 {
			rtt = 100 * time.Millisecond
		}
		bw = float64(b.cwnd) * 8.0 / rtt.Seconds()
	}
	r := b.pacingGain * bw
	if r < 1 {
		r = 1
	}
	return Bandwidth(r)
}

func (b *bbrSender) minPipeCwnd() protocol.ByteCount {
	return protocol.ByteCount(bbrMinPipePkts) * b.maxDatagramSize
}

// ---- SendAlgorithm ----

func (b *bbrSender) TimeUntilSend(_ protocol.ByteCount) monotime.Time {
	return b.pacer.TimeUntilSend()
}

func (b *bbrSender) HasPacingBudget(now monotime.Time) bool {
	if b.pacer.Budget(now) < b.maxDatagramSize {
		b.lastBlocked = now // pacing-limited => network is the limiter
		return false
	}
	return true
}

func (b *bbrSender) CanSend(bytesInFlight protocol.ByteCount) bool {
	if bytesInFlight >= b.cwnd {
		b.lastBlocked = b.clock.Now() // cwnd-limited => network is the limiter
		return false
	}
	return true
}

func (b *bbrSender) OnPacketSent(sentTime monotime.Time, _ protocol.ByteCount, pn protocol.PacketNumber, bytes protocol.ByteCount, isRetransmittable bool) {
	b.pacer.SentPacket(sentTime, bytes)
	if !isRetransmittable {
		return
	}
	b.largestSent = pn
	if b.roundStartPN == protocol.InvalidPacketNumber {
		b.roundStartPN = pn
	}
	b.inflight += bytes
	b.sent[pn] = bbrSentState{sentTime: sentTime, delivered: b.delivered}
}

func (b *bbrSender) OnPacketAcked(pn protocol.PacketNumber, ackedBytes protocol.ByteCount, _ protocol.ByteCount, eventTime monotime.Time) {
	if !b.started {
		b.cycleStamp = eventTime
		b.probeRTTStamp = eventTime
		b.started = true
	}
	b.delivered += ackedBytes
	if ackedBytes <= b.inflight {
		b.inflight -= ackedBytes
	} else {
		b.inflight = 0
	}

	// RTprop = propagation delay = the MINIMUM RTT. We use quic-go's MinRTT, which
	// is the connection's all-time min computed from raw send-deltas — it tracks the
	// propagation floor and (unlike a latest-sample filter) can NEVER be polluted by
	// a queued/inflated sample, which would otherwise inflate cwnd and cause
	// bufferbloat on a congested path. (Trade-off vs canonical 10s windowing: it
	// won't rise if the path's true min RTT increases — fine for fixed-latency links;
	// PROBE_RTT still fires every 10s to drain and re-probe.)
	if mr := b.rttStats.MinRTT(); mr > 0 {
		if b.rtProp <= 0 || mr < b.rtProp {
			b.rtProp = mr
			b.probeRTTStamp = eventTime // RTprop just refreshed at a new minimum
		}
	}

	// app-limited iff we have NOT been blocked by cwnd/pacing within ~1 RTprop. We
	// can't see the app's send queue through this interface, so we infer the limiter
	// from recent network-limited rejections (set in CanSend/HasPacingBudget). When
	// app-limited, the delivery-rate sample must NOT depress BtlBw (see field doc).
	limitThresh := b.rtProp
	if limitThresh < 10*time.Millisecond {
		limitThresh = 10 * time.Millisecond
	}
	b.appLimited = b.lastBlocked.IsZero() || eventTime.Sub(b.lastBlocked) > limitThresh

	// delivery-rate sample (BBR): bytes delivered between this packet's send and its
	// ack, over that interval. Feeds the windowed-max BtlBw estimate — unless we are
	// app-limited, in which case the sample only reflects how little the app offered.
	if s, ok := b.sent[pn]; ok {
		if iv := eventTime.Sub(s.sentTime); iv > 0 && !b.appLimited {
			rate := float64(b.delivered-s.delivered) * 8.0 / iv.Seconds()
			if rate > 0 {
				b.bwWin = append(b.bwWin, bwSample{round: b.roundCount, bw: rate})
			}
		}
		delete(b.sent, pn)
	}

	// round accounting: a round trip completes when we ack a packet sent at/after the
	// packet number that marked the start of the round.
	if b.roundStartPN != protocol.InvalidPacketNumber && pn >= b.roundStartPN {
		b.roundCount++
		b.roundStartPN = b.largestSent
	}

	// evict bw samples older than the filter window, then take the max.
	b.btlBw = b.windowedMaxBw()

	b.updateModel(eventTime)
}

func (b *bbrSender) windowedMaxBw() float64 {
	var lo uint64
	if b.roundCount > bbrBwFilterLen {
		lo = b.roundCount - bbrBwFilterLen
	}
	out := b.bwWin[:0]
	var best float64
	for _, s := range b.bwWin {
		if s.round < lo {
			continue
		}
		out = append(out, s)
		if s.bw > best {
			best = s.bw
		}
	}
	b.bwWin = out
	return best
}

// updateModel runs the BBR state machine + recomputes cwnd and the pacing gain.
func (b *bbrSender) updateModel(now monotime.Time) {
	switch b.mode {
	case bbrStartup:
		// exit when BtlBw stops growing >=25% for 3 rounds.
		if b.btlBw >= b.fullBw*bbrFullBwThresh {
			b.fullBw = b.btlBw
			b.fullBwCount = 0
		} else {
			b.fullBwCount++
			if b.fullBwCount >= bbrFullBwCnt {
				b.fullBwReached = true
				b.mode = bbrDrain
				b.pacingGain = bbrDrainGain
				b.cwndGain = bbrHighGain
			}
		}
	case bbrDrain:
		// leave Drain once the queue Startup built has drained to ~1 BDP (compare
		// ACTUAL inflight to the BDP — the old code compared BDP to itself, so it
		// always passed and skipped Drain entirely).
		if b.inflight <= b.bdp() {
			b.enterProbeBW(now)
		}
	case bbrProbeBW:
		// advance the 8-phase pacing-gain cycle once per RTprop.
		if b.rtProp > 0 && now.Sub(b.cycleStamp) >= b.rtProp {
			b.cycleStamp = now
			b.cycleIndex = (b.cycleIndex + 1) % len(bbrProbeBWGains)
			b.pacingGain = bbrProbeBWGains[b.cycleIndex]
			b.cwndGain = bbrCwndGainProbe
		}
	case bbrProbeRTT:
		// hold cwnd=4·MTU for the probe, then restore: back to Startup if BtlBw
		// never plateaued, else ProbeBW (canonical — don't jump a still-ramping
		// flow straight into steady-state cruising).
		if now.Sub(b.probeRTTStart) >= bbrProbeRTTDur {
			b.probeRTTStamp = now
			if b.fullBwReached {
				b.enterProbeBW(now)
			} else {
				b.mode = bbrStartup
				b.pacingGain = bbrHighGain
				b.cwndGain = bbrHighGain
			}
		}
	}

	// PROBE_RTT: every 10s force a short cwnd=4·MTU drain to refresh RTprop.
	if b.mode != bbrProbeRTT && now.Sub(b.probeRTTStamp) >= bbrProbeRTTIvl {
		b.priorMode = b.mode
		b.mode = bbrProbeRTT
		b.pacingGain = 1
		b.cwndGain = 1
		b.probeRTTStart = now
	}

	// cwnd = cwnd_gain · BDP + 3·MTU quanta (covers delayed/aggregated ACKs, per
	// Linux bbr_quantization_budget), floored at 4·MTU; ProbeRTT pins it to 4·MTU.
	if b.mode == bbrProbeRTT {
		b.cwnd = b.minPipeCwnd()
	} else if b.btlBw > 0 && b.rtProp > 0 {
		c := b.cwndOf(b.cwndGain) + 3*b.maxDatagramSize
		if c < b.minPipeCwnd() {
			c = b.minPipeCwnd()
		}
		b.cwnd = c
	} // else: no model yet — keep the current (initial) cwnd

	if b.debug && now.Sub(b.lastDbg) >= 500*time.Millisecond {
		b.lastDbg = now
		fmt.Fprintf(os.Stderr, "BBRDBG mode=%d btlBw=%.3fMbps rtProp=%dus cwnd=%dB inflight=%dB pgain=%.2f cgain=%.1f appLim=%v fullBw=%v pacer=%.3fMbps bwSamples=%d\n",
			b.mode, b.btlBw/1e6, b.rtProp.Microseconds(), int(b.cwnd), int(b.inflight),
			b.pacingGain, b.cwndGain, b.appLimited, b.fullBwReached,
			float64(b.bandwidthForPacer())/1e6, len(b.bwWin))
	}
}

func (b *bbrSender) enterProbeBW(now monotime.Time) {
	b.mode = bbrProbeBW
	b.pacingGain = 1
	b.cwndGain = bbrCwndGainProbe
	b.cycleIndex = 0
	b.cycleStamp = now
}

// cwndOf returns gain · BDP in bytes (BDP = BtlBw · RTprop), floored at 4·MTU.
func (b *bbrSender) cwndOf(gain float64) protocol.ByteCount {
	if b.btlBw <= 0 || b.rtProp <= 0 {
		return b.cwnd // keep current until we have a model
	}
	c := protocol.ByteCount(gain * b.btlBw / 8.0 * b.rtProp.Seconds())
	if c < b.minPipeCwnd() {
		c = b.minPipeCwnd()
	}
	return c
}

// bdp is the bandwidth-delay product (BtlBw · RTprop) in bytes, with NO gain and
// NO quanta — the Drain target. Floored at the minimum pipe before a model exists.
func (b *bbrSender) bdp() protocol.ByteCount {
	if b.btlBw <= 0 || b.rtProp <= 0 {
		return b.minPipeCwnd()
	}
	return protocol.ByteCount(b.btlBw / 8.0 * b.rtProp.Seconds())
}

// OnCongestionEvent: BBR is rate-based and does NOT cut cwnd on loss (the whole
// point — loss-resilience). We just account the loss and free the per-packet state.
func (b *bbrSender) OnCongestionEvent(pn protocol.PacketNumber, lostBytes, _ protocol.ByteCount) {
	b.connStats.PacketsLost.Add(1)
	b.connStats.BytesLost.Add(uint64(lostBytes))
	if lostBytes <= b.inflight {
		b.inflight -= lostBytes
	} else {
		b.inflight = 0
	}
	delete(b.sent, pn)
}

func (b *bbrSender) OnRetransmissionTimeout(packetsRetransmitted bool) {
	if packetsRetransmitted {
		// full RTO: lost the model's pipe estimate; restart conservatively.
		b.cwnd = b.minPipeCwnd()
	}
}

func (b *bbrSender) MaybeExitSlowStart() {} // BBR has its own startup-exit logic

func (b *bbrSender) SetMaxDatagramSize(s protocol.ByteCount) {
	b.maxDatagramSize = s
	b.pacer.SetMaxDatagramSize(s)
	if b.cwnd < b.minPipeCwnd() {
		b.cwnd = b.minPipeCwnd()
	}
}

// ---- SendAlgorithmWithDebugInfos ----

func (b *bbrSender) InSlowStart() bool             { return b.mode == bbrStartup }
func (b *bbrSender) InRecovery() bool              { return false }
func (b *bbrSender) GetCongestionWindow() protocol.ByteCount { return b.cwnd }
