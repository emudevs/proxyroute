package tunnel

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/header"
)

func dnsFixtureQuery(id byte) []byte {
	return []byte{0, id, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 4, 't', 'e', 's', 't', 0, 0, 1, 0, 1}
}

func dnsFixtureAnswer(query []byte, negative bool) []byte {
	out := append([]byte(nil), query...)
	out[2], out[3] = 0x81, 0x80
	if !negative {
		out[7] = 1
		return append(out, 0xc0, 12, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 192, 0, 2, 1)
	}
	out[3], out[9] = 0x83, 1
	out = append(out, 0xc0, 12, 0, 6, 0, 1, 0, 0, 0, 60, 0, 24, 0xc0, 12, 0xc0, 12)
	return append(out, 0, 0, 0, 1, 0, 0, 0, 10, 0, 0, 0, 10, 0, 0, 0, 10, 0, 0, 0, 15)
}

func TestDNSCacheTTLAndNegativeExpiry(t *testing.T) {
	for _, negative := range []bool{false, true} {
		cache := new(dnsCache)
		query := dnsFixtureQuery(1)
		entry := cacheableAnswer("key", query, len(query), dnsFixtureAnswer(query, negative))
		if entry == nil {
			t.Fatal("expected cacheable response")
		}
		cache.put(entry)
		lifetime := uint32(60)
		if negative {
			lifetime = 15
		}
		data := cache.get("key", entry.inserted.Add(4*time.Second))
		if ttl := binary.BigEndian.Uint32(data[len(query)+6:]); ttl != lifetime-4 {
			t.Fatalf("wrong aged TTL: %d, want %d", ttl, lifetime-4)
		}
		if cache.get("key", entry.inserted.Add(time.Duration(lifetime)*time.Second)) != nil {
			t.Fatal("returned expired record")
		}
	}
}

func TestDNSCacheRouteAndTransactionID(t *testing.T) {
	cache := new(dnsCache)
	var calls int
	load := func(q []byte) ([]byte, error) {
		calls++
		return dnsFixtureAnswer(q, false), nil
	}
	for i, direct := range []bool{false, false, true, true} {
		reply, _, err := cache.resolve(context.Background(), direct, dnsFixtureQuery(byte(i)), load)
		if err != nil || reply[1] != byte(i) {
			t.Fatalf("reply %x: %v", reply, err)
		}
	}
	if calls != 2 {
		t.Fatalf("got %d upstream calls, want 2", calls)
	}
	failed := func(q []byte) ([]byte, error) {
		calls++
		return nil, errors.New("temporary")
	}
	newPolicy := new(dnsCache)
	for i := range 2 {
		if _, _, err := newPolicy.resolve(context.Background(), false, dnsFixtureQuery(byte(i)), failed); err == nil {
			t.Fatal("temporary DNS failure disappeared")
		}
	}
	if calls != 4 {
		t.Fatal("temporarily failed results were cached")
	}
}

func TestDNSConcurrentQueriesShareUpstream(t *testing.T) {
	cache := new(dnsCache)
	var calls atomic.Int32
	load := func(q []byte) ([]byte, error) {
		calls.Add(1)
		time.Sleep(20 * time.Millisecond)
		return dnsFixtureAnswer(q, false), nil
	}
	var group sync.WaitGroup
	for i := range 32 {
		group.Add(1)
		go func() {
			defer group.Done()
			reply, _, err := cache.resolve(context.Background(), false, dnsFixtureQuery(byte(i)), load)
			if err != nil || reply[1] != byte(i) {
				t.Errorf("request %d got %x: %v", i, reply, err)
			}
		}()
	}
	group.Wait()
	if calls.Load() != 1 {
		t.Fatalf("got %d upstream requests, want 1", calls.Load())
	}
}

func TestCapabilityBackoffAndRecovery(t *testing.T) {
	var c circuit
	now := time.Now()
	a, b := netip.MustParseAddr("2001:db8:1::1"), netip.MustParseAddr("2001:db8:2::1")
	if c.at(now) != unknown || c.failed(a, now) != 1 || c.failed(a, now) != 1 || c.failed(b, now) != 2 {
		t.Fatal("repeated destinations counted as independent evidence")
	}
	if c.at(now) != degraded || !c.retry.IsZero() {
		t.Fatal("failed destinations alone tripped IPv6 circuit")
	}
	c.postpone(now)
	if c.at(now) != unavailable || c.retry.Sub(now) != 30*time.Second {
		t.Fatal("first backoff incorrect")
	}
	c.postpone(now.Add(31 * time.Second))
	if c.backoff != 60*time.Second {
		t.Fatal("retry did not increase backoff")
	}
	c.succeeded(now.Add(32 * time.Second))
	if c.at(now.Add(32*time.Second)) != supported || !c.retry.IsZero() || c.at(now.Add(time.Hour)) != unknown {
		t.Fatal("successful IPv6 evidence did not recover or expire")
	}
}

func TestUDPPolicyKeepsFamiliesAndProtocolsSeparate(t *testing.T) {
	e := &Engine{ipMode: "auto", quicMode: "auto"}
	ipv4 := netip.MustParseAddr("192.0.2.1")
	ipv6 := netip.MustParseAddr("2001:db8::1")
	for _, address := range []string{"192.0.2.1", "198.51.100.1", "203.0.113.1"} {
		e.udpObserved(netip.MustParseAddr(address), true, false)
	}
	if e.allowQUIC(ipv4) || !e.allowQUIC(ipv6) || e.checkIP(ipv6, false) != nil {
		t.Fatal("UDP/443 circuit affected the wrong protocol or family")
	}
	e.quicMode = "enabled"
	if !e.allowQUIC(ipv4) {
		t.Fatal("explicit QUIC mode did not bypass auto failure")
	}
	e.ipMode = "ipv4"
	if !errors.Is(e.checkIP(ipv6, false), errIPv6Unavailable) || e.checkIP(ipv4, true) != nil {
		t.Fatal("IPv4 setting did not restrict only IPv6")
	}
}

func TestHTTPUDPRejectsInsideTunnel(t *testing.T) {
	t.Setenv("GODEBUG", "netdns=go")
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pair[0])
	defer unix.Close(pair[1])
	e, err := Start(pair[0], testHooks{"proxy", make(chan string, 16)}, "http", "127.0.0.1", "127.0.0.1", 1, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Stop()
	request := make([]byte, header.IPv4MinimumSize+header.UDPMinimumSize+4)
	ip := header.IPv4(request)
	ip.Encode(&header.IPv4Fields{TotalLength: uint16(len(request)), TTL: 64, Protocol: uint8(header.UDPProtocolNumber),
		SrcAddr: tcpip.AddrFrom4([4]byte{10, 99, 0, 1}), DstAddr: tcpip.AddrFrom4([4]byte{198, 51, 100, 7})})
	ip.SetChecksum(^ip.CalculateChecksum())
	udp := header.UDP(request[header.IPv4MinimumSize:])
	udp.Encode(&header.UDPFields{SrcPort: 33333, DstPort: 443, Length: uint16(len(udp))})
	copy(udp.Payload(), "ping")
	if _, err := unix.Write(pair[1], request); err != nil {
		t.Fatal(err)
	}
	poll := []unix.PollFd{{Fd: int32(pair[1]), Events: unix.POLLIN}}
	if n, err := unix.Poll(poll, 2000); n != 1 || err != nil {
		t.Fatalf("no local ICMP error: %d %v", n, err)
	}
	reply := make([]byte, 1500)
	n, err := unix.Read(pair[1], reply)
	if err != nil || n < 28 || reply[9] != uint8(header.ICMPv4ProtocolNumber) ||
		reply[20] != 3 || reply[21] != 3 {
		t.Fatalf("invalid local ICMP port-unreachable: %x (%v)", reply[:max(n, 0)], err)
	}
}

func BenchmarkDNSRepeatedQuery(b *testing.B) {
	for _, enabled := range []bool{false, true} {
		name := "upstream"
		if enabled {
			name = "cached"
		}
		b.Run(name, func(b *testing.B) {
			cache := new(dnsCache)
			query := dnsFixtureQuery(1)
			var calls int
			load := func(q []byte) ([]byte, error) { calls++; return dnsFixtureAnswer(q, false), nil }
			b.ReportAllocs()
			for b.Loop() {
				if enabled {
					_, _, _ = cache.resolve(context.Background(), false, query, load)
				} else {
					_, _ = load(query)
				}
			}
			b.ReportMetric(float64(calls)/float64(b.N), "upstream/op")
		})
	}
}

type readerOnly struct{ io.Reader }
type writerOnly struct{ io.Writer }

func BenchmarkTCPPumpBuffers(b *testing.B) {
	p := bytes.Repeat([]byte{42}, 512*1024)
	for _, pooled := range []bool{false, true} {
		name := "io-copy"
		if pooled {
			name = "pooled"
		}
		b.Run(name, func(b *testing.B) {
			b.SetBytes(int64(len(p)))
			b.ReportAllocs()
			for b.Loop() {
				source := readerOnly{bytes.NewReader(p)}
				dst := writerOnly{io.Discard}
				if pooled {
					buf := tcpBuffers.Get().(*[32 * 1024]byte)
					_, _ = io.CopyBuffer(dst, source, buf[:])
					tcpBuffers.Put(buf)
				} else {
					_, _ = io.Copy(dst, source)
				}
			}
		})
	}
}

type refuseProtection struct{ testHooks }

func (refuseProtection) Protect(int) bool { return false }

func TestSocketProtectionStopsUpstreamDial(t *testing.T) {
	d := protectedDial(refuseProtection{})
	for _, network := range []string{"tcp4", "udp4", "tcp6", "udp6"} {
		address := "127.0.0.1:1"
		if network[3] == '6' {
			address = "[::1]:1"
		}
		c, err := d.DialContext(context.Background(), network, address)
		if c != nil {
			c.Close()
		}
		if !errors.Is(err, errSocketProtection) {
			t.Errorf("%s escaped failed protection: %v", network, err)
		}
	}
}

func TestSOCKSUDPRejectsWrongDestinationAndFragment(t *testing.T) {
	target := "[2001:db8::123]:443"
	address, _ := encodeAddress(target)
	packet := append(append([]byte{0, 0, 0}, address...), []byte("reply")...)
	if payload, valid := udpPayload(packet, target); !valid || string(payload) != "reply" {
		t.Fatal("did not accept the expected destination")
	}
	if _, valid := udpPayload(packet, "[2001:db8::124]:443"); valid {
		t.Fatal("accepted a different destination")
	}
	packet[2] = 1
	if _, valid := udpPayload(packet, target); valid {
		t.Fatal("accepted an unsupported SOCKS5 fragment")
	}
}
