package tunnel

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"time"
)

var udpBuffers = sync.Pool{New: func() any { return new([65535]byte) }}

const (
	udpIdle           = 45 * time.Second
	quicFirstResponse = 4 * time.Second
)

func relayAddress(remote string, proxy endpoint) (string, error) {
	host, port, err := net.SplitHostPort(remote)
	if err != nil || port == "0" {
		return "", errUDPRelay
	}
	ip := net.ParseIP(host)
	if ip != nil && ip.IsUnspecified() {
		host = proxy.IP
	}
	if net.ParseIP(host) == nil {
		// Never resolve a name supplied by the relay on the system resolver.
		if !strings.EqualFold(host, proxy.Host) || net.ParseIP(proxy.IP) == nil {
			return "", errUDPRelay
		}
		host = proxy.IP
	}
	return net.JoinHostPort(host, port), nil
}

func udpPayload(packet []byte, target string) ([]byte, bool) {
	if len(packet) < 4 || packet[0] != 0 || packet[1] != 0 || packet[2] != 0 {
		return nil, false
	}
	r := bytes.NewReader(packet[4:])
	source, err := readAddress(r, packet[3])
	if err != nil || source != target {
		return nil, false
	}
	return packet[len(packet)-r.Len():], true
}

func (f *flow) udp(target, route string) error {
	e := f.e
	ip := targetIP(target)
	direct := route == "direct"
	f.stage = "policy"
	if !direct {
		if err := e.checkIP(ip, false); err != nil {
			return err
		}
		if e.proxy.Protocol != "socks5" {
			return errUDPUnsupported
		}
		e.caps.mu.Lock()
		noAssociate := e.caps.assoc.at(time.Now()) == unsupported
		e.caps.mu.Unlock()
		if noAssociate {
			return errUDPUnsupported
		}
	}

	var header []byte
	if !direct {
		address, err := encodeAddress(target)
		if err != nil {
			return err
		}
		header = append([]byte{0, 0, 0}, address...)
	}
	outgoing := udpBuffers.Get().(*[65535]byte)
	defer udpBuffers.Put(outgoing)
	copy(outgoing[:], header)
	f.app.SetReadDeadline(time.Now().Add(udpIdle))
	n, err := f.app.Read(outgoing[len(header):])
	if err != nil {
		return quietTimeout(err)
	}
	quic := !direct && strings.HasSuffix(target, ":443") && quicInitial(outgoing[len(header):len(header)+n])
	if quic && !e.allowQUIC(ip) {
		return errQUICUnavailable
	}

	var control net.Conn
	remote := target
	if !direct {
		f.stage = "udp_associate"
		ctx, cancel := context.WithTimeout(e.ctx, 6*time.Second)
		control, remote, err = e.proxy.connectTimed(ctx, e.dial, 3, "0.0.0.0:0", &f.connect)
		cancel()
		if err != nil {
			var rejection proxyRejection
			if errors.As(err, &rejection) && !rejection.http && rejection.status == 7 {
				e.caps.mu.Lock()
				e.caps.assoc = observation{unsupported, time.Now().Add(evidenceLifetime)}
				e.caps.mu.Unlock()
				return errUDPUnsupported
			}
			return err
		}
		defer control.Close()
		e.caps.mu.Lock()
		e.caps.assoc = observation{supported, time.Now().Add(evidenceLifetime)}
		e.caps.mu.Unlock()
		proxy := e.proxy
		proxy.IP, _, _ = net.SplitHostPort(control.RemoteAddr().String())
		remote, err = relayAddress(remote, proxy)
		if err != nil {
			return err
		}
	}

	f.stage = "udp_relay"
	socket, err := e.dial.DialContext(e.ctx, "udp", remote)
	if err != nil {
		if errors.Is(err, errSocketProtection) || e.ctx.Err() != nil {
			return err
		}
		return errUDPRelay
	}
	defer socket.Close()
	stop := context.AfterFunc(e.ctx, func() {
		socket.Close()
		if control != nil {
			control.Close()
		}
	})
	defer stop()
	firstDeadline := time.Now().Add(quicFirstResponse)
	var activity sync.Mutex
	responded := false
	touch := func(response bool) {
		activity.Lock()
		defer activity.Unlock()
		if response && !responded {
			responded = true
			if !direct {
				e.udpObserved(ip, quic, true)
			}
		}
		until := time.Now().Add(udpIdle)
		if quic && !responded {
			until = firstDeadline
		}
		f.app.SetReadDeadline(until)
		socket.SetReadDeadline(until)
	}
	touch(false)
	socket.SetWriteDeadline(time.Now().Add(5 * time.Second))
	if _, err = socket.Write(outgoing[:len(header)+n]); err != nil {
		return errUDPRelay
	}
	f.account(n, true)
	f.stage = "udp_transfer"

	var controlDone chan struct{}
	if control != nil {
		controlDone = make(chan struct{})
		go func() {
			defer close(controlDone)
			var invalid [1]byte
			control.Read(invalid[:]) // EOF, an error or unexpected control data ends the association.
			socket.Close()
		}()
	}
	done := make(chan error, 2)
	go func() {
		for {
			n, err := f.app.Read(outgoing[len(header):])
			if err != nil {
				done <- err
				return
			}
			socket.SetWriteDeadline(time.Now().Add(5 * time.Second))
			if _, err = socket.Write(outgoing[:len(header)+n]); err != nil {
				done <- err
				return
			}
			f.account(n, true)
			touch(false)
		}
	}()
	go func() {
		incoming := udpBuffers.Get().(*[65535]byte)
		defer udpBuffers.Put(incoming)
		for {
			n, err := socket.Read(incoming[:])
			if err != nil {
				done <- err
				return
			}
			payload := incoming[:n]
			if !direct {
				var valid bool
				payload, valid = udpPayload(payload, target)
				if !valid {
					continue
				}
			}
			touch(true)
			f.app.SetWriteDeadline(time.Now().Add(5 * time.Second))
			n, err = f.app.Write(payload)
			f.account(n, false)
			if err != nil {
				done <- err
				return
			}
		}
	}()
	result := <-done
	socket.Close()
	f.app.Close()
	<-done
	if controlDone != nil {
		control.Close()
		<-controlDone
	}
	if e.ctx.Err() != nil || direct {
		return quietTimeout(result)
	}
	var networkErr net.Error
	timeout := errors.As(result, &networkErr) && networkErr.Timeout()
	if !responded && f.up.Load() > 0 && timeout {
		e.udpObserved(ip, quic, false)
		return errUDPNoResponse
	}
	if !responded && !timeout && !errors.Is(result, net.ErrClosed) && !errors.Is(result, io.EOF) {
		return errUDPRelay
	}
	return quietTimeout(result)
}
