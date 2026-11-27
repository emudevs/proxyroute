package tunnel

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	unknown          = "UNKNOWN"
	supported        = "SUPPORTED"
	unsupported      = "UNSUPPORTED"
	degraded         = "DEGRADED"
	unavailable      = "TEMPORARILY_UNAVAILABLE"
	evidenceLifetime = 10 * time.Minute
)

var (
	errIPv6Unavailable  = errors.New("IPV6_UNAVAILABLE")
	errUDPUnsupported   = errors.New("UDP_UNSUPPORTED")
	errUDPRelay         = errors.New("UDP_RELAY_UNREACHABLE")
	errUDPNoResponse    = errors.New("UDP_NO_RESPONSE")
	errQUICUnavailable  = errors.New("QUIC_UNAVAILABLE")
	errSocketProtection = errors.New("SOCKET_PROTECTION_FAILED")
)

type observation struct {
	state string
	until time.Time
}

func (o observation) at(now time.Time) string {
	if now.Before(o.until) {
		return o.state
	}
	return unknown
}

type circuit struct {
	observation
	retry    time.Time
	failures map[netip.Prefix]struct{}
	backoff  time.Duration
}

func (c *circuit) failed(addr netip.Addr, now time.Time) int {
	if c.at(now) == unknown {
		c.failures = nil
		c.backoff = 0
		c.retry = time.Time{}
	}
	if c.failures == nil {
		c.failures = make(map[netip.Prefix]struct{})
	}
	if len(c.failures) < 3 {
		bits := 24
		if addr.Is6() {
			bits = 48
		}
		c.failures[netip.PrefixFrom(addr, bits).Masked()] = struct{}{}
	}
	state := degraded
	if now.Before(c.retry) {
		state = unavailable
	}
	c.observation = observation{state, now.Add(evidenceLifetime)}
	return len(c.failures)
}

func (c *circuit) succeeded(now time.Time) {
	*c = circuit{observation: observation{supported, now.Add(evidenceLifetime)}}
}

func (c *circuit) postpone(now time.Time) {
	c.backoff = min(max(2*c.backoff, 30*time.Second), 4*time.Minute)
	c.retry = now.Add(c.backoff)
	c.observation = observation{unavailable, now.Add(evidenceLifetime)}
}

type capabilities struct {
	mu                                    sync.Mutex
	ipv4TCP, ipv4UDP, ipv6UDP, assoc, doh observation
	ipv6TCP                               circuit
	udp443                                [2]circuit
	probing                               bool
	nextProbe                             time.Time
	tcpMillis, handshakeMillis            time.Duration
	tcpSucceeded, tcpFailed               uint64
}

func targetIP(target string) netip.Addr {
	host, _, _ := net.SplitHostPort(target)
	ip, _ := netip.ParseAddr(host)
	return ip.Unmap()
}

func family(ip netip.Addr) int {
	if ip.Is6() {
		return 1
	}
	return 0
}

func (e *Engine) recordTCP(ip netip.Addr, elapsed connectTiming, err error) {
	c := &e.caps
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	if err == nil {
		c.tcpSucceeded++
		c.tcpMillis, c.handshakeMillis = elapsed.dial, elapsed.handshake
		if ip.Is6() {
			c.ipv6TCP.succeeded(now)
		} else {
			c.ipv4TCP = observation{supported, now.Add(evidenceLifetime)}
		}
		return
	}
	if e.ctx.Err() != nil {
		return
	}
	c.tcpFailed++
	if !ip.Is6() || !elapsed.target || !elapsed.addressFailure || e.ipMode != "auto" {
		return
	}
	c.ipv6TCP.failed(ip, now)
}

func (e *Engine) checkIP(ip netip.Addr, tcp bool) error {
	if !ip.Is6() {
		return nil
	}
	if e.ipMode == "ipv4" {
		return errIPv6Unavailable
	}
	if !tcp || e.ipMode != "auto" {
		return nil
	}
	now := time.Now()
	c := &e.caps
	c.mu.Lock()
	reject := now.Before(c.ipv6TCP.retry)
	// Trigger only on demand and only after two different destination prefixes
	// fail at the target stage. A working IPv4 control is required to trip it.
	probe := len(c.ipv6TCP.failures) >= 2 && c.ipv6TCP.at(now) != unknown &&
		!reject && !c.probing && !now.Before(c.nextProbe)
	if probe {
		c.probing = true
		c.nextProbe = now.Add(30 * time.Second)
	}
	c.mu.Unlock()
	if probe {
		e.startCapabilityProbe()
	}
	if reject {
		return errIPv6Unavailable
	}
	return nil
}

func (e *Engine) startCapabilityProbe() {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.stopping {
		return
	}
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		// Verified TLS over the current proxy to the same endpoint on both
		// families. These probes never resolve locally or send DNS questions.
		type outcome struct {
			v6  bool
			err error
		}
		ctx, cancel := context.WithTimeout(e.ctx, 5*time.Second)
		defer cancel()
		results := make(chan outcome, 2)
		for _, ip := range []string{"1.1.1.1", "2606:4700:4700::1111"} {
			go func(ip string) {
				_, err := checkTLS(ctx, e.proxy, e.dial, net.JoinHostPort(ip, "443"))
				results <- outcome{strings.Contains(ip, ":"), err}
			}(ip)
		}
		var v4, v6 error
		for range 2 {
			result := <-results
			if result.v6 {
				v6 = result.err
			} else {
				v4 = result.err
			}
		}
		now := time.Now()
		c := &e.caps
		c.mu.Lock()
		c.probing = false
		if e.ctx.Err() == nil {
			if v6 == nil {
				c.ipv6TCP.succeeded(now)
			} else if v4 == nil && len(c.ipv6TCP.failures) >= 2 &&
				c.ipv6TCP.at(now) == degraded && !errors.Is(v6, errSocketProtection) {
				c.ipv6TCP.postpone(now)
			}
		}
		c.mu.Unlock()
	}()
}

func (e *Engine) dnsObserved(ok bool) {
	c := &e.caps
	now := time.Now()
	c.mu.Lock()
	if ok {
		c.doh = observation{supported, now.Add(evidenceLifetime)}
	} else if c.doh.at(now) != supported {
		c.doh = observation{degraded, now.Add(time.Minute)}
	}
	c.mu.Unlock()
}

func (e *Engine) udpObserved(ip netip.Addr, quic bool, ok bool) {
	c := &e.caps
	now := time.Now()
	c.mu.Lock()
	defer c.mu.Unlock()
	udp := &c.ipv4UDP
	if ip.Is6() {
		udp = &c.ipv6UDP
	}
	if ok {
		*udp = observation{supported, now.Add(evidenceLifetime)}
		if quic {
			c.udp443[family(ip)].succeeded(now)
		}
	} else {
		if udp.at(now) != supported {
			*udp = observation{degraded, now.Add(time.Minute)}
		}
		if quic && c.udp443[family(ip)].failed(ip, now) >= 3 && e.quicMode == "auto" {
			c.udp443[family(ip)].postpone(now)
		}
	}
}

func (e *Engine) allowQUIC(ip netip.Addr) bool {
	if e.quicMode == "disabled" {
		return false
	}
	c := &e.caps
	c.mu.Lock()
	defer c.mu.Unlock()
	return e.quicMode != "auto" || !time.Now().Before(c.udp443[family(ip)].retry)
}

// QUIC v1/v2 client Initials have a long, fixed-bit header and a minimum
// 1200-byte UDP datagram. Unknown versions and other UDP are passed through.
func quicInitial(data []byte) bool {
	if len(data) < 1200 || data[0]&0xc0 != 0xc0 {
		return false
	}
	switch binary.BigEndian.Uint32(data[1:5]) {
	case 1:
		return data[0]&0x30 == 0
	case 0x6b3343cf:
		return data[0]&0x30 == 0x10
	}
	return false
}

type counters struct {
	tcp, udp, dns           atomic.Int64
	dropped                 atomic.Int64
	hits, misses, coalesced atomic.Int64
}

// Diagnostics is a point-in-time snapshot for the active profile/physical
// network pair. Closing the engine invalidates this snapshot and the cache.
func (e *Engine) Diagnostics() string {
	now := time.Now()
	c := &e.caps
	c.mu.Lock()
	defer c.mu.Unlock()
	assoc, u4, u6 := c.assoc.at(now), c.ipv4UDP.at(now), c.ipv6UDP.at(now)
	q4, q6 := c.udp443[0].at(now), c.udp443[1].at(now)
	v6 := c.ipv6TCP.at(now)
	if e.proxy.Protocol != "socks5" && e.proxy.Protocol != "direct" {
		assoc, u4, u6, q4, q6 = unsupported, unsupported, unsupported, unsupported, unsupported
	}
	if e.ipMode == "ipv4" {
		v6, u6, q6 = unsupported, unsupported, unsupported
	}
	return fmt.Sprintf("ipv4_tcp=%s;ipv6_tcp=%s;ipv4_udp=%s;ipv6_udp=%s;socks5_udp=%s;udp443_ipv4=%s;udp443_ipv6=%s;doh=%s;tcp_ms=%d;handshake_ms=%d;tcp_ok=%d;tcp_failed=%d;active_tcp=%d;active_udp=%d;active_dns=%d;flow_limit=%d;dns_hits=%d;dns_misses=%d;dns_coalesced=%d",
		c.ipv4TCP.at(now), v6, u4, u6, assoc, q4, q6, c.doh.at(now), c.tcpMillis.Milliseconds(), c.handshakeMillis.Milliseconds(),
		c.tcpSucceeded, c.tcpFailed, e.metrics.tcp.Load(), e.metrics.udp.Load(), e.metrics.dns.Load(),
		e.metrics.dropped.Load(), e.metrics.hits.Load(), e.metrics.misses.Load(), e.metrics.coalesced.Load())
}
