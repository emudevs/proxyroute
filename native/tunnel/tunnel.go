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
	h              Hooks
	proxy          endpoint
	dial           *net.Dialer
	doh            *http.Client
	directDoH      *http.Client
	resolver       string
	filterAds      bool
	filterTrackers bool
	dnsDirect      bool
	ctx            context.Context
	cancel         context.CancelFunc
	stack          *stack.Stack
	mu             sync.Mutex
	stopping       bool
	wg             sync.WaitGroup
	done           chan struct{}
	ids            atomic.Int64
	sent           atomic.Int64
	received       atomic.Int64
	sampling       atomic.Bool
	activity       chan struct{}
	slots          chan struct{}
}

func Start(fd int, h Hooks, protocol, host, ip string, port int, user, password string, firewallOnly bool) (*Engine, error) {
	return StartConfigured(fd, h, protocol, host, ip, port, user, password, firewallOnly,
		"https://cloudflare-dns.com/dns-query", "1.1.1.1", false, false, false)
}

func StartConfigured(fd int, h Hooks, protocol, host, ip string, port int, user, password string, firewallOnly bool,
	resolver, bootstrap string, filterAds, filterTrackers, dnsDirect bool) (*Engine, error) {
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
		done: make(chan struct{}), slots: make(chan struct{}, 512), activity: make(chan struct{}, 1)}
	e.doh = dnsClient(proxy, dial, dnsAddress)
	e.directDoH = dnsClient(endpoint{Protocol: "direct"}, dial, dnsAddress)
	e.stack, err = core.CreateStack(&core.Config{LinkEndpoint: dev, TransportHandler: e})
	if err != nil {
		cancel()
		dev.Close()
		e.wg.Wait()
		return nil, err
	}
	e.wg.Add(1)
	go e.sample()
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
	e.mu.Lock()
	if e.stopping {
		e.mu.Unlock()
		conn.Close()
		return
	}
	select {
	case e.slots <- struct{}{}:
		e.wg.Add(1)
	default:
		e.mu.Unlock()
		conn.Close()
		return
	}
	e.mu.Unlock()
	go func() {
		defer e.wg.Done()
		defer func() { <-e.slots }()
		defer conn.Close()
		stop := context.AfterFunc(e.ctx, func() { conn.Close() })
		defer stop()
		uid := e.h.Owner(protocol, id.RemoteAddress.String(), int(id.RemotePort), id.LocalAddress.String(), int(id.LocalPort))
		route := e.h.Route(uid)
		if route == "proxy" && e.proxy.Protocol == "direct" {
			route = "direct"
		}
		destination := net.JoinHostPort(id.LocalAddress.String(), strconv.Itoa(int(id.LocalPort)))
		key := e.ids.Add(1)
		kind := "TCP"
		if protocol == 17 {
			kind = "UDP"
		}
		virtualResolver := id.LocalAddress.String() == dnsIPv4 || id.LocalAddress.String() == dnsIPv6
		isDNS := virtualResolver && id.LocalPort == 53
		if isDNS {
			kind = "DNS/" + kind
		}
		e.h.Opened(key, uid, kind, destination, route)
		f := &flow{e: e, app: conn}
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
		}
		result := "closed"
		if err != nil && !errors.Is(err, io.EOF) && !errors.Is(err, net.ErrClosed) {
			if e.ctx.Err() != nil {
				result = "VPN stopped"
			} else {
				result = err.Error()
			}
		}
		e.h.Closed(key, result, f.up.Load(), f.down.Load())
	}()
}

func (e *Engine) HandleTCP(c adapter.TCPConn) { e.launch(c, c.ID(), 6) }
func (e *Engine) HandleUDP(c adapter.UDPConn) { e.launch(c, c.ID(), 17) }

type flow struct {
	e        *Engine
	app      net.Conn
	up, down atomic.Int64
}

func (f *flow) account(n int, outgoing bool) {
	if n == 0 {
		return
	}
	if outgoing {
		f.up.Add(int64(n))
		f.e.sent.Add(int64(n))
	} else {
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

func (f *flow) tcp(target, route string) error {
	p := f.e.proxy
	if route == "direct" {
		p = endpoint{Protocol: "direct"}
	}
	upstream, _, err := p.connect(f.e.ctx, f.e.dial, 1, target)
	if err != nil {
		return err
	}
	defer upstream.Close()
	stop := context.AfterFunc(f.e.ctx, func() { upstream.Close() })
	defer stop()
	results := make(chan error, 2)
	pump := func(dst, src net.Conn, outgoing bool) {
		_, err := io.Copy(metered{dst, f, outgoing}, src)
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
	if first != nil {
		return first
	}
	return second
}

func (f *flow) dns(protocol int, route string, uid int) error {
	c := f.e.doh
	if route == "direct" || f.e.dnsDirect {
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
			response, err = dnsQuery(f.e.ctx, c, f.e.resolver, packet[:n])
		}
		if err != nil {
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
