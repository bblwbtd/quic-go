package congestion

import (
	"fmt"
	"testing"
	"time"

	"github.com/quic-go/quic-go/internal/monotime"
	"github.com/quic-go/quic-go/internal/protocol"
	"github.com/quic-go/quic-go/internal/utils"
)

// bbr_diag_test.go — an event-driven bottleneck+loss simulator to OBSERVE whether
// the BBR sender's btlBw/cwnd collapse under heavy loss for an APP-LIMITED flow
// (offered « bottleneck, like XNC's 10 Mbps over a 50 Mbps link). It drives the
// real CanSend/HasPacingBudget/OnPacketSent/OnPacketAcked path so app-limited
// detection is exercised. Prints the trajectory; asserts no floor-collapse.
// Run: go test ./internal/congestion/ -run TestBBRDiag -v
func TestBBRDiag(t *testing.T) {
	// offered=10 => app-limited (well below the 50Mbps bottleneck, like XNC);
	// offered=200 => network-limited (fills the pipe, exercises Startup->Drain->ProbeBW).
	cases := []struct {
		offeredMbps float64
		burstGap    time.Duration // 0 = smooth; >0 = release offered bytes in bursts this often
	}{
		{10.0, 0},                    // app-limited, smoothly paced
		{200.0, 0},                   // network-limited (fills the pipe)
		{10.0, 20 * time.Millisecond}, // app-limited but BURSTY (like XNC sensor dumps)
	}
	for _, c := range cases {
		t.Run(fmt.Sprintf("offered=%.0fMbps_burst=%s", c.offeredMbps, c.burstGap), func(t *testing.T) {
			runBBRDiag(t, c.offeredMbps, c.burstGap)
		})
	}
}

func runBBRDiag(t *testing.T, offeredMbps float64, burstGap time.Duration) {
	const mtu = protocol.ByteCount(1280)
	const rtt = 50 * time.Millisecond
	const bottleneckMbps = 50.0

	bottleneckBps := bottleneckMbps * 1e6
	offeredBps := offeredMbps * 1e6

	var clock mockClock
	rttStats := &utils.RTTStats{}
	connStats := &utils.ConnectionStats{}
	b := NewBBRSender(&clock, rttStats, connStats, mtu, nil)
	rttStats.UpdateRTT(rtt, 0)

	type inflightPkt struct {
		pn         protocol.PacketNumber
		arriveTime monotime.Time
		lost       bool
	}
	var inflight []inflightPkt
	var bytesInFlight protocol.ByteCount
	pn := protocol.PacketNumber(0)

	// bottleneck serialization: next time the link is free to deliver a packet
	var linkFree monotime.Time

	phases := []struct {
		label  string
		dur    time.Duration
		loss   float64
	}{
		{"clean", 2 * time.Second, 0.0},
		{"loss30", 2 * time.Second, 0.30},
		{"blackout", 1 * time.Second, 1.0},
		{"recover48", 3 * time.Second, 0.48},
	}

	fmt.Printf("bottleneck=%.0fMbps offered=%.0fMbps rtt=%s mtu=%d floor=%dB\n",
		bottleneckMbps, offeredMbps, rtt, mtu, 4*mtu)

	const dt = 1 * time.Millisecond
	var appCredit float64       // bytes the app is allowed to send (token bucket)
	var backlog int             // packets queued by the app, awaiting a send slot
	var lastBurst monotime.Time // last time credit was released into the backlog
	deliveredInWindow := 0
	var winStart monotime.Time
	minBtlBw := 1e18
	var sawFloor bool
	modesSeen := map[bbrMode]bool{}

	for pi := range phases {
		ph := phases[pi]
		phaseEnd := clock.Now().Add(ph.dur)
		// deterministic per-phase loss via a counter
		var sentInPhase int
		for clock.Now() < phaseEnd {
			now := clock.Now()
			// 1) process arrivals (ack delivered, congestion-event lost)
			kept := inflight[:0]
			for _, p := range inflight {
				if p.arriveTime <= now {
					bytesInFlight -= mtu
					if p.lost {
						b.OnCongestionEvent(p.pn, mtu, bytesInFlight)
					} else {
						b.OnPacketAcked(p.pn, mtu, bytesInFlight, now)
						deliveredInWindow++
					}
				} else {
					kept = append(kept, p)
				}
			}
			inflight = kept

			// 2a) the app produces data at the offered rate. burstGap==0 => release
			// every step (smooth); burstGap>0 => accumulate and dump in bursts (XNC).
			appCredit += offeredBps / 8.0 * dt.Seconds()
			if burstGap == 0 || now.Sub(lastBurst) >= burstGap {
				for appCredit >= float64(mtu) {
					backlog++
					appCredit -= float64(mtu)
				}
				lastBurst = now
			}

			// 2b) drain the backlog through the sender; stop when blocked or empty.
			for backlog > 0 {
				if !b.CanSend(bytesInFlight) || !b.HasPacingBudget(now) {
					break // network-limited: defer (sets lastBlocked inside)
				}
				serviceGap := time.Duration(float64(mtu) * 8.0 / bottleneckBps * float64(time.Second))
				if linkFree < now {
					linkFree = now
				}
				linkFree = linkFree.Add(serviceGap)
				lost := false
				if ph.loss > 0 {
					sentInPhase++
					if float64(sentInPhase%100) < ph.loss*100 {
						lost = true
					}
				}
				arrive := linkFree.Add(rtt)
				b.OnPacketSent(now, bytesInFlight, pn, mtu, true)
				bytesInFlight += mtu
				inflight = append(inflight, inflightPkt{pn: pn, arriveTime: arrive, lost: lost})
				pn++
				backlog--
			}

			modesSeen[b.mode] = true

			// sample btlBw floor (skip startup warmup)
			if now.Sub(monotime.Time(0)) > rtt && b.btlBw > 0 && b.btlBw < minBtlBw {
				minBtlBw = b.btlBw
			}
			if b.GetCongestionWindow() <= 4*mtu && now.Sub(monotime.Time(0)) > time.Second {
				sawFloor = true
			}

			// periodic print
			if now.Sub(winStart) >= 500*time.Millisecond {
				dMbps := float64(deliveredInWindow) * float64(mtu) * 8.0 / now.Sub(winStart).Seconds() / 1e6
				fmt.Printf("[%-9s t=%4dms] mode=%d btlBw=%6.2fMbps cwnd=%5dB(%3dpkt) pacer=%6.2fMbps inflight=%3dpkt appLim=%v deliv=%.1fMbps\n",
					ph.label, int64(now.Sub(monotime.Time(0))/time.Millisecond), b.mode, b.btlBw/1e6,
					int(b.GetCongestionWindow()), int(b.GetCongestionWindow()/mtu),
					float64(b.bandwidthForPacer())/1e6, len(inflight), b.appLimited, dMbps)
				winStart = now
				deliveredInWindow = 0
			}
			clock.Advance(dt)
		}
	}
	fmt.Printf("RESULT: min btlBw=%.3f Mbps  sawFloorCollapse=%v  modesSeen{startup:%v drain:%v probeBW:%v probeRTT:%v}\n",
		minBtlBw/1e6, sawFloor,
		modesSeen[bbrStartup], modesSeen[bbrDrain], modesSeen[bbrProbeBW], modesSeen[bbrProbeRTT])
	if sawFloor {
		t.Errorf("cwnd collapsed to the 4·MTU floor — app-limited death spiral NOT fixed")
	}
	// A pipe-filling flow must transit Startup->Drain->ProbeBW (the old always-true
	// Drain-exit skipped Drain). App-limited flows stay in Startup/ProbeBW (btlBw
	// can't grow), so only assert the transit when we actually filled the pipe.
	if offeredMbps > bottleneckMbps && !modesSeen[bbrDrain] {
		t.Errorf("network-limited flow never entered DRAIN — Startup->Drain->ProbeBW broken")
	}
}
