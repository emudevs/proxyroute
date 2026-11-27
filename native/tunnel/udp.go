package tunnel

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"time"
)

func (f *flow) udp(target, route string) error {
	var control net.Conn
	remote := target
	direct := route == "direct"
	if !direct {
		if f.e.proxy.Protocol != "socks5" {
			return errors.New("UDP unavailable over HTTP CONNECT")
		}
		var err error
		control, remote, err = f.e.proxy.connect(f.e.ctx, f.e.dial, 3, "0.0.0.0:0")
		if err != nil {
			return err
		}
		defer control.Close()
		host, port, err := net.SplitHostPort(remote)
		if err != nil || port == "0" {
			return errors.New("invalid SOCKS5 UDP relay")
		}
		ip := net.ParseIP(host)
		if ip != nil && ip.IsUnspecified() {
			host = f.e.proxy.IP
		}
		if net.ParseIP(host) == nil {
			// Relay names must be the configured proxy name. Avoid resolving
			// proxy-supplied names on the Android system resolver.
			if host != f.e.proxy.Host {
				return errors.New("SOCKS5 UDP relay requires an IP address")
			}
			host = f.e.proxy.IP
		}
		remote = net.JoinHostPort(host, port)
	}
	socket, err := f.e.dial.DialContext(f.e.ctx, "udp", remote)
	if err != nil {
		return err
	}
	defer socket.Close()
	stop := closeOnCancel(f.e, socket, control)
	defer stop()
	var header []byte
	if !direct {
		address, err := encodeAddress(target)
		if err != nil {
			return err
		}
		header = append([]byte{0, 0, 0}, address...)
	}
	done := make(chan error, 2)
	if control != nil {
		go func() { io.Copy(io.Discard, control); socket.Close() }()
	}
	touch := func() {
		until := time.Now().Add(45 * time.Second)
		f.app.SetDeadline(until)
		socket.SetDeadline(until)
	}
	touch()
	go func() {
		buf := make([]byte, 65535)
		copy(buf, header)
		for {
			n, err := f.app.Read(buf[len(header):])
			if err != nil {
				done <- quietTimeout(err)
				return
			}
			touch()
			_, err = socket.Write(buf[:len(header)+n])
			if err != nil {
				done <- quietTimeout(err)
				return
			}
			f.account(n, true)
		}
	}()
	go func() {
		buf := make([]byte, 65535)
		for {
			n, err := socket.Read(buf)
			if err != nil {
				done <- quietTimeout(err)
				return
			}
			payload := buf[:n]
			if !direct {
				if n < 4 || payload[0] != 0 || payload[1] != 0 || payload[2] != 0 {
					continue
				}
				r := bytes.NewReader(payload[4:])
				source, err := readAddress(r, payload[3])
				if err != nil || source != target {
					continue
				}
				payload = payload[n-r.Len():]
			}
			touch()
			n, err = f.app.Write(payload)
			f.account(n, false)
			if err != nil {
				done <- quietTimeout(err)
				return
			}
		}
	}()
	result := <-done
	socket.Close()
	f.app.Close()
	<-done
	return result
}

func closeOnCancel(e *Engine, socket, control net.Conn) func() bool {
	return context.AfterFunc(e.ctx, func() {
		socket.Close()
		if control != nil {
			control.Close()
		}
	})
}
