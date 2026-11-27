package tunnel

import (
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"sync"
	"sync/atomic"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/core"
	"github.com/xjasonlyu/tun2socks/v2/core/adapter"
	"github.com/xjasonlyu/tun2socks/v2/core/device/fdbased"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
)

const (
	dnsIPv4 = "10.99.0.2"
	dnsIPv6 = "fd72:6f75:7465::2"
	mtu     = 1500
)

type Hooks interface {
	Protect(fd int) bool
	Owner(protocol int, source string, sourcePort int, target string, targetPort int) int
	Route(uid int) string
	Opened(id int64, uid int, protocol string, target string, route string)
	Closed(id int64, result string, sent int64, received int64)
	Traffic(sent int64, received int64)
}

type Engine struct {
	h                Hooks
	proxy            endpoint
	dial             *net.Dialer
	doh              *http.Client
	directDoH        *http.Client
	resolver         string
	filterAds        bool
	filterTrackers   bool
	dnsDirect        bool
	ctx              context.Context
	cancel           context.CancelFunc
	stack            *stack.Stack
	mu               sync.Mutex
	stopping         bool
	wg               sync.WaitGroup
	done             chan struct{}
	ids              atomic.Int64
	sent             atomic.Int64
	received         atomic.Int64
	sampling         atomic.Bool
	activity         chan struct{}
	slots            chan struct{}
	ipMode, quicMode string
	caps             capabilities
	metrics          counters
	cache            *dnsCache
	dnsSlots         chan struct{}
}

func Start(fd int, h Hooks, protocol, host, ip string, port int, user, password string, firewallOnly bool) (*Engine, error) {
	return StartConfigured(fd, h, protocol, host, ip, port, user, password, firewallOnly,
		"https://cloudflare-dns.com/dns-query", "1.1.1.1", false, false, false)
}

func StartConfigured(fd int, h Hooks, protocol, host, ip string, port int, user, password string, firewallOnly bool,
	resolver, bootstrap string, filterAds, filterTrackers, dnsDirect bool) (*Engine, error) {
	return StartPerformance(fd, h, protocol, host, ip, port, user, password, firewallOnly,
		resolver, bootstrap, filterAds, filterTrackers, dnsDirect, "auto", "auto", true)
}

func StartPerformance(fd int, h Hooks, protocol, host, ip string, port int, user, password string, firewallOnly bool,
	resolver, bootstrap string, filterAds, filterTrackers, dnsDirect bool, ipMode, quicMode string, cacheDNS bool) (*Engine, error) {
	if ipMode != "ipv4" && ipMode != "dual" {
		ipMode = "auto"
	}
	if quicMode != "enabled" && quicMode != "disabled" {
		quicMode = "auto"
	}
	uri, err := url.Parse(resolver)
	if err != nil || uri.Scheme != "https" || uri.Hostname() == "" || uri.User != nil || net.ParseIP(bootstrap) == nil {
		return nil, errors.New("invalid DNS-over-HTTPS configuration")
	}
	dnsPort := uri.Port()
	if dnsPort == "" {
		dnsPort = "443"
	}
	dnsAddress := net.JoinHostPort(bootstrap, dnsPort)
	copyFD, err := unix.Dup(fd)
	if err != nil {
		return nil, err
	}
	unix.CloseOnExec(copyFD)
	dev, err := fdbased.Open(strconv.Itoa(copyFD), mtu, 0)
	if err != nil {
		unix.Close(copyFD)
		return nil, err
	}
	ctx, cancel := context.WithCancel(context.Background())
	proxy := endpoint{protocol, host, ip, port, user, password}
	if firewallOnly {
		proxy = endpoint{Protocol: "direct"}
	}
	dial := protectedDial(h)
	e := &Engine{h: h, proxy: proxy, dial: dial, ctx: ctx, cancel: cancel,
		resolver: resolver, filterAds: filterAds, filterTrackers: filterTrackers, dnsDirect: dnsDirect,
		done: make(chan struct{}), slots: make(chan struct{}, 496), dnsSlots: make(chan struct{}, 16),
		activity: make(chan struct{}, 1), ipMode: ipMode, quicMode: quicMode}
	if cacheDNS {
		e.cache = &dnsCache{}
	}
	e.doh = dnsClient(proxy, dial, dnsAddress)
	e.directDoH = dnsClient(endpoint{Protocol: "direct"}, dial, dnsAddress)
	link := &delayedLink{LinkEndpoint: dev}
	e.stack, err = core.CreateStack(&core.Config{LinkEndpoint: link, TransportHandler: e})
	if err != nil {
		cancel()
		dev.Close()
		e.wg.Wait()
		return nil, err
	}
	installUDPHandler(e)
	e.wg.Add(1)
	go e.sample()
	link.activate()
	return e, nil
}

func (e *Engine) Stop() {
	e.mu.Lock()
	if e.stopping {
		e.mu.Unlock()
		<-e.done
		return
	}
	e.stopping = true
	e.mu.Unlock()
	e.cancel()
	e.stack.Close()
	e.wg.Wait()
	// Wait detaches the NIC and closes its link endpoint, which owns the
	// duplicated TUN fd. Closing it here as well can close a reused fd.
	e.stack.Wait()
	e.doh.CloseIdleConnections()
	e.directDoH.CloseIdleConnections()
	e.flushTraffic()
	close(e.done)
}

func (e *Engine) sample() {
	defer e.wg.Done()
	for {
		select {
		case <-e.activity:
		case <-e.ctx.Done():
			return
		}
		timer := time.NewTimer(3 * time.Second)
		select {
		case <-timer.C:
			e.sampling.Store(false)
			e.flushTraffic()
		case <-e.ctx.Done():
			timer.Stop()
			return
		}
	}
}

func (e *Engine) flushTraffic() {
	up, down := e.sent.Swap(0), e.received.Swap(0)
	if up != 0 || down != 0 {
		e.h.Traffic(up, down)
	}
}

func (e *Engine) launch(conn net.Conn, id *stack.TransportEndpointID, protocol int) {
	e.dispatch(conn, id, protocol, nil, nil)
}

func (e *Engine) launchUDP(conn net.Conn, id *stack.TransportEndpointID, release func(), reject func(error)) {
	e.dispatch(conn, id, 17, release, reject)
}

func (e *Engine) dispatch(conn net.Conn, id *stack.TransportEndpointID, protocol int, release func(), reject func(error)) {
	targetIP := id.LocalAddress.String()
	virtualResolver := targetIP == dnsIPv4 || targetIP == dnsIPv6
	isDNS := virtualResolver && id.LocalPort == 53
	slots, active := e.slots, &e.metrics.tcp
	switch {
	case isDNS:
		slots, active = e.dnsSlots, &e.metrics.dns
	case protocol == 17:
		active = &e.metrics.udp
	}
	e.mu.Lock()
	if e.stopping {
		e.mu.Unlock()
		conn.Close()
		if release != nil {
			release()
		}
		return
	}
	select {
	case slots <- struct{}{}:
		e.wg.Add(1)
	default:
		e.metrics.dropped.Add(1)
		e.mu.Unlock()
		conn.Close()
		if release != nil {
			release()
		}
		return
	}
	e.mu.Unlock()
	go func() {
		defer e.wg.Done()
		active.Add(1)
		defer active.Add(-1)
		defer func() { <-slots }()
		defer conn.Close()
		if release != nil {
			defer release()
		}
		stop := context.AfterFunc(e.ctx, func() { conn.Close() })
		defer stop()
		uid := e.h.Owner(protocol, id.RemoteAddress.String(), int(id.RemotePort), targetIP, int(id.LocalPort))
		route := e.h.Route(uid)
		if route == "proxy" && e.proxy.Protocol == "direct" {
			route = "direct"
		}
		destination := net.JoinHostPort(targetIP, strconv.Itoa(int(id.LocalPort)))
		key := e.ids.Add(1)
		kind := "TCP"
		if protocol == 17 {
			kind = "UDP"
		}
		if isDNS {
			kind = "DNS/" + kind
		}
		e.h.Opened(key, uid, kind, destination, route)
		f := &flow{e: e, app: conn, started: time.Now()}
		var err error
		switch {
		case route == "block":
			err = errors.New("blocked by application rule")
		case isDNS:
			err = f.dns(protocol, route, uid)
		case virtualResolver:
			err = errors.New("unsupported port on the virtual DNS resolver")
		case protocol == 6:
			err = f.tcp(destination, route)
		default:
			err = f.udp(destination, route)
			if reject != nil && route == "proxy" && e.ctx.Err() == nil {
				reject(err)
			}
		}
		result := "closed"
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
			if e.ctx.Err() != nil {
				result = "VPN stopped"
			} else {
				result = err.Error()
			}
		}
		if metrics, ok := e.h.(PerformanceHooks); ok {
			metrics.Finished(key, result, f.up.Load(), f.down.Load(), f.connect.dial.Milliseconds(),
				f.connect.handshake.Milliseconds(), f.firstByte.Load(), f.dnsMillis, f.stage)
		} else {
			e.h.Closed(key, result, f.up.Load(), f.down.Load())
		}
	}()
}

func (e *Engine) HandleTCP(c adapter.TCPConn) { e.launch(c, c.ID(), 6) }
func (e *Engine) HandleUDP(c adapter.UDPConn) { e.launch(c, c.ID(), 17) }

// PerformanceHooks is optional so the original Start/Check callers keep working.
type PerformanceHooks interface {
	Finished(id int64, result string, sent, received, tcpMillis, handshakeMillis, firstByteMillis, dnsMillis int64, stage string)
}

type flow struct {
	e                   *Engine
	app                 net.Conn
	up, down, firstByte atomic.Int64
	started             time.Time
	connect             connectTiming
	dnsMillis           int64
	stage               string
}

func (f *flow) account(n int, outgoing bool) {
	if n == 0 {
		return
	}
	if outgoing {
		f.up.Add(int64(n))
		f.e.sent.Add(int64(n))
	} else {
		if !f.started.IsZero() && f.firstByte.Load() == 0 {
			f.firstByte.CompareAndSwap(0, max(1, time.Since(f.started).Milliseconds()))
		}
		f.down.Add(int64(n))
		f.e.received.Add(int64(n))
	}
	if f.e.sampling.CompareAndSwap(false, true) {
		f.e.activity <- struct{}{}
	}
}

type metered struct {
	io.Writer
	f  *flow
	up bool
}

func (m metered) Write(p []byte) (int, error) {
	n, err := m.Writer.Write(p)
	m.f.account(n, m.up)
	return n, err
}

var tcpBuffers = sync.Pool{New: func() any { return new([32 * 1024]byte) }}

func (f *flow) tcp(target, route string) error {
	p := f.e.proxy
	if route == "direct" {
		p = endpoint{Protocol: "direct"}
	}
	ip := targetIP(target)
	if p.Protocol != "direct" {
		if err := f.e.checkIP(ip, true); err != nil {
			f.stage = "policy"
			return err
		}
	}
	upstream, _, err := p.connectTimed(f.e.ctx, f.e.dial, 1, target, &f.connect)
	if p.Protocol != "direct" {
		f.e.recordTCP(ip, f.connect, err)
	}
	if err != nil {
		f.stage = "tcp_connect"
		if f.connect.handshake != 0 {
			f.stage = "proxy_handshake"
		}
		return err
	}
	defer upstream.Close()
	stop := context.AfterFunc(f.e.ctx, func() { upstream.Close() })
	defer stop()
	results := make(chan error, 2)
	pump := func(dst, src net.Conn, outgoing bool) {
		buf := tcpBuffers.Get().(*[32 * 1024]byte)
		defer tcpBuffers.Put(buf)
		_, err := io.CopyBuffer(metered{dst, f, outgoing}, src, buf[:])
		if half, ok := dst.(interface{ CloseWrite() error }); ok {
			half.CloseWrite()
		}
		results <- err
	}
	go pump(upstream, f.app, true)
	go pump(f.app, upstream, false)
	first := <-results
	if first != nil {
		f.app.Close()
		upstream.Close()
	}
	second := <-results
	if first != nil || second != nil {
		f.stage = "tcp_transfer"
	}
	if first != nil {
		return first
	}
	return second
}

func (f *flow) dns(protocol int, route string, uid int) error {
	c := f.e.doh
	direct := route == "direct" || f.e.dnsDirect
	if direct {
		c = f.e.directDoH
	}
	var packet [65535]byte
	for {
		f.app.SetReadDeadline(time.Now().Add(30 * time.Second))
		var n int
		var err error
		if protocol == 6 {
			_, err = io.ReadFull(f.app, packet[:2])
			if err != nil {
				return quietTimeout(err)
			}
			n = int(binary.BigEndian.Uint16(packet[:2]))
			_, err = io.ReadFull(f.app, packet[:n])
		} else {
			n, err = f.app.Read(packet[:])
		}
		if err != nil {
			return quietTimeout(err)
		}
		if n < 12 {
			return errors.New("invalid DNS packet")
		}
		f.account(n, true)
		name, questionEnd := dnsQuestion(packet[:n])
		var response []byte
		if questionEnd > 0 && blockedDNS(name, f.e.filterAds, f.e.filterTrackers) {
			response = negativeDNS(packet[:questionEnd], 3)
			key := f.e.ids.Add(1)
			f.e.h.Opened(key, uid, "DNS", name, "block")
			f.e.h.Closed(key, "blocked by DNS filter", int64(n), int64(len(response)))
		} else {
			start := time.Now()
			load := func(query []byte) ([]byte, error) {
				result, err := dnsQuery(f.e.ctx, c, f.e.resolver, query)
				if !direct && f.e.ctx.Err() == nil {
					f.e.dnsObserved(err == nil)
				}
				return result, err
			}
			var event string
			if f.e.cache != nil {
				response, event, err = f.e.cache.resolve(f.e.ctx, direct, packet[:n], load)
			} else {
				response, err = load(packet[:n])
			}
			switch event {
			case "DNS_CACHE_HIT":
				f.e.metrics.hits.Add(1)
			case "DNS_CACHE_MISS":
				f.e.metrics.misses.Add(1)
			case "DNS_REQUEST_COALESCED":
				f.e.metrics.coalesced.Add(1)
			}
			f.dnsMillis = time.Since(start).Milliseconds()
		}
		if err != nil {
			f.stage = "doh"
			// SERVFAIL with the original transaction ID so the resolver
			// can retry without leaking the query outside the configured route.
			end := questionEnd
			if end == 0 {
				end = 12
			}
			response = negativeDNS(packet[:end], 2)
		}
		if protocol == 6 {
			response = append([]byte{byte(len(response) >> 8), byte(len(response))}, response...)
		}
		f.app.SetWriteDeadline(time.Now().Add(5 * time.Second))
		written, writeErr := f.app.Write(response)
		f.account(written, false)
		if writeErr != nil {
			return writeErr
		}
		if err != nil {
			return err
		}
	}
}

func dnsQuery(ctx context.Context, c *http.Client, resolver string, query []byte) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, resolver, bytes.NewReader(query))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/dns-message")
	req.Header.Set("Accept", "application/dns-message")
	res, err := c.Do(req)
	if err != nil {
		return nil, err
	}
	defer res.Body.Close()
	if res.StatusCode != 200 {
		return nil, errors.New("DNS-over-HTTPS request refused")
	}
	data, err := io.ReadAll(io.LimitReader(res.Body, 65536))
	if err != nil {
		return nil, err
	}
	if len(data) < 12 || len(data) > 65535 || !bytes.Equal(data[:2], query[:2]) || data[2]&0x80 == 0 {
		return nil, errors.New("invalid DNS-over-HTTPS response")
	}
	return data, nil
}

func quietTimeout(err error) error {
	var e net.Error
	if errors.As(err, &e) && e.Timeout() {
		return nil
	}
	return err
}
