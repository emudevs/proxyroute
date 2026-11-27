package tunnel

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type endpoint struct {
	Protocol string
	Host     string
	IP       string
	Port     int
	User     string
	Password string
}

func protectedDial(h Hooks) *net.Dialer {
	return &net.Dialer{Timeout: 10 * time.Second, KeepAlive: -1,
		Control: func(_, _ string, raw syscall.RawConn) error {
			var protected bool
			if err := raw.Control(func(fd uintptr) { protected = h.Protect(int(fd)) }); err != nil {
				return err
			}
			if !protected {
				return errors.New("Android socket protection refused")
			}
			return nil
		},
	}
}

type bufferedConn struct {
	net.Conn
	reader *bufio.Reader
}

func (b *bufferedConn) Read(p []byte) (int, error) { return b.reader.Read(p) }
func (b *bufferedConn) CloseWrite() error {
	if c, ok := b.Conn.(interface{ CloseWrite() error }); ok {
		return c.CloseWrite()
	}
	return nil
}

func (p endpoint) connect(ctx context.Context, d *net.Dialer, command byte, target string) (net.Conn, string, error) {
	if p.Protocol == "direct" {
		c, err := d.DialContext(ctx, "tcp", target)
		return c, "", err
	}
	c, err := d.DialContext(ctx, "tcp", net.JoinHostPort(p.IP, strconv.Itoa(p.Port)))
	if err != nil {
		return nil, "", err
	}
	raw := c
	stop := context.AfterFunc(ctx, func() { raw.Close() })
	defer stop()
	br := bufio.NewReader(c)
	var bound string
	c.SetDeadline(time.Now().Add(12 * time.Second))
	switch p.Protocol {
	case "socks5":
		bound, err = p.socks(c, command, target)
	case "https", "http":
		if command != 1 {
			err = errors.New("HTTP CONNECT supports TCP only")
			break
		}
		if p.Protocol == "https" {
			tc := tls.Client(c, &tls.Config{ServerName: p.Host, MinVersion: tls.VersionTLS12})
			if err = tc.HandshakeContext(ctx); err != nil {
				break
			}
			c = tc
			br.Reset(c)
		}
		err = p.httpConnect(c, br, target)
	default:
		err = errors.New("unknown proxy protocol")
	}
	if err != nil {
		c.Close()
		return nil, "", err
	}
	c.SetDeadline(time.Time{})
	if p.Protocol == "http" || p.Protocol == "https" {
		c = &bufferedConn{c, br}
	}
	return c, bound, nil
}

func (p endpoint) httpConnect(c net.Conn, reader *bufio.Reader, target string) error {
	request := "CONNECT " + target + " HTTP/1.1\r\nHost: " + target + "\r\n"
	if p.User != "" || p.Password != "" {
		request += "Proxy-Authorization: Basic " + base64.StdEncoding.EncodeToString([]byte(p.User+":"+p.Password)) + "\r\n"
	}
	if _, err := io.WriteString(c, request+"\r\n"); err != nil {
		return err
	}
	// Parse only the tunnel response headers. The buffered reader retains payload
	// bytes received with the response, including a server-first greeting.
	line, err := reader.ReadSlice('\n')
	if err != nil {
		return err
	}
	parts := strings.Fields(string(line))
	if len(parts) < 2 || !strings.HasPrefix(parts[0], "HTTP/") {
		return errors.New("invalid CONNECT response")
	}
	status, err := strconv.Atoi(parts[1])
	if err != nil || status < 100 || status > 599 {
		return errors.New("invalid CONNECT status")
	}
	if status < 200 || status >= 300 {
		return fmt.Errorf("proxy rejected CONNECT (%d)", status)
	}
	for total := len(line); total < 32768; {
		line, err = reader.ReadSlice('\n')
		if err != nil {
			return err
		}
		if string(line) == "\r\n" || string(line) == "\n" {
			return nil
		}
		total += len(line)
	}
	return errors.New("CONNECT headers too large")
}

func encodeAddress(address string) ([]byte, error) {
	host, portString, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.ParseUint(portString, 10, 16)
	if err != nil {
		return nil, err
	}
	ip := net.ParseIP(host)
	var out []byte
	switch {
	case ip.To4() != nil:
		out = append([]byte{1}, ip.To4()...)
	case ip.To16() != nil:
		out = append([]byte{4}, ip.To16()...)
	case len(host) > 0 && len(host) <= 255:
		out = append([]byte{3, byte(len(host))}, host...)
	default:
		return nil, errors.New("invalid SOCKS address")
	}
	return append(out, byte(port>>8), byte(port)), nil
}

func readAddress(r io.Reader, atyp byte) (string, error) {
	var size int
	switch atyp {
	case 1:
		size = 4
	case 4:
		size = 16
	case 3:
		var count [1]byte
		if _, err := io.ReadFull(r, count[:]); err != nil {
			return "", err
		}
		size = int(count[0])
	default:
		return "", errors.New("invalid SOCKS response address")
	}
	data := make([]byte, size+2)
	if _, err := io.ReadFull(r, data); err != nil {
		return "", err
	}
	host := string(data[:size])
	if atyp != 3 {
		host = net.IP(data[:size]).String()
	}
	return net.JoinHostPort(host, strconv.Itoa(int(data[size])<<8|int(data[size+1]))), nil
}

func (p endpoint) socks(c net.Conn, command byte, target string) (string, error) {
	method := byte(0)
	if p.User != "" || p.Password != "" {
		method = 2
	}
	if _, err := c.Write([]byte{5, 1, method}); err != nil {
		return "", err
	}
	var choice [2]byte
	if _, err := io.ReadFull(c, choice[:]); err != nil {
		return "", err
	}
	if choice != [2]byte{5, method} {
		return "", errors.New("SOCKS5 authentication method refused")
	}
	if method == 2 {
		if len(p.User) == 0 || len(p.User) > 255 || len(p.Password) == 0 || len(p.Password) > 255 {
			return "", errors.New("SOCKS5 requires username and password of 1–255 bytes")
		}
		auth := append([]byte{1, byte(len(p.User))}, p.User...)
		auth = append(append(auth, byte(len(p.Password))), p.Password...)
		if _, err := c.Write(auth); err != nil {
			return "", err
		}
		if _, err := io.ReadFull(c, choice[:]); err != nil {
			return "", err
		}
		if choice != [2]byte{1, 0} {
			return "", errors.New("SOCKS5 authentication refused")
		}
	}
	address, err := encodeAddress(target)
	if err != nil {
		return "", err
	}
	if _, err = c.Write(append([]byte{5, command, 0}, address...)); err != nil {
		return "", err
	}
	var reply [4]byte
	if _, err = io.ReadFull(c, reply[:]); err != nil {
		return "", err
	}
	if reply[0] != 5 || reply[1] != 0 || reply[2] != 0 {
		return "", fmt.Errorf("SOCKS5 request rejected (%d)", reply[1])
	}
	return readAddress(c, reply[3])
}

func Check(h Hooks, protocol, host, ip string, port int, user, password string) (int64, error) {
	start := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 12*time.Second)
	defer cancel()
	p := endpoint{protocol, host, ip, port, user, password}
	c, _, err := p.connect(ctx, protectedDial(h), 1, "1.1.1.1:443")
	if err != nil {
		return 0, err
	}
	defer c.Close()
	tc := tls.Client(c, &tls.Config{ServerName: "cloudflare-dns.com", MinVersion: tls.VersionTLS12})
	if err = tc.HandshakeContext(ctx); err != nil {
		return 0, err
	}
	return time.Since(start).Milliseconds(), nil
}

func dnsClient(doh endpoint, dial *net.Dialer, destination string) *http.Client {
	return &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			ForceAttemptHTTP2: true, MaxIdleConnsPerHost: 2, IdleConnTimeout: 60 * time.Second,
			DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
				c, _, err := doh.connect(ctx, dial, 1, destination)
				return c, err
			},
			TLSClientConfig: &tls.Config{MinVersion: tls.VersionTLS12},
		},
	}
}
