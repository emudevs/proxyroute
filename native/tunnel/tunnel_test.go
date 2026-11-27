package tunnel

import (
	"bufio"
	"context"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/xjasonlyu/tun2socks/v2/core/device/fdbased"
	"golang.org/x/sys/unix"
	"gvisor.dev/gvisor/pkg/tcpip"
	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/network/ipv4"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/tcp"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
)

type testHooks struct {
	rule string
	log  chan string
}

func (h testHooks) Protect(int) bool                        { return true }
func (h testHooks) Owner(int, string, int, string, int) int { return 10001 }
func (h testHooks) Route(int) string                        { return h.rule }
func (h testHooks) Opened(_ int64, _ int, proto, target, route string) {
	h.log <- proto + " " + target + " " + route
}
func (h testHooks) Closed(_ int64, result string, sent, received int64) {
	h.log <- fmt.Sprintf("%s %d %d", result, sent, received)
}
func (h testHooks) Traffic(sent, received int64) {
	h.log <- fmt.Sprintf("traffic %d %d", sent, received)
}

func serveOnce(t *testing.T, serve func(net.Conn) error) (string, int, <-chan error) {
	t.Helper()
	l, err := net.Listen("tcp4", "0.0.0.0:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	results := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			results <- err
			return
		}
		defer c.Close()
		c.SetDeadline(time.Now().Add(6 * time.Second))
		results <- serve(c)
	}()
	addr := l.Addr().(*net.TCPAddr)
	return "127.0.0.1", addr.Port, results
}

func TestHTTPConnectPreservesBufferedBytes(t *testing.T) {
	ip, port, done := serveOnce(t, func(c net.Conn) error {
		req, err := http.ReadRequest(bufio.NewReader(c))
		if err != nil {
			return err
		}
		want := "Basic " + base64.StdEncoding.EncodeToString([]byte("demo:secret"))
		if req.Method != "CONNECT" || req.Host != "127.0.0.1:8443" || req.Header.Get("Proxy-Authorization") != want {
			return fmt.Errorf("wrong CONNECT request")
		}
		_, err = io.WriteString(c, "HTTP/1.1 200 OK\r\n\r\nready")
		return err
	})
	p := endpoint{"http", ip, ip, port, "demo", "secret"}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	c, _, err := p.connect(ctx, protectedDial(testHooks{}), 1, "127.0.0.1:8443")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	reply, err := io.ReadAll(c)
	if err != nil || string(reply) != "ready" {
		t.Fatalf("reply %q, error %v", reply, err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestHTTPSProxyUsesTLSAndChecksName(t *testing.T) {
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != "CONNECT" || r.Host != "example.com:443" {
			http.Error(w, "invalid request", 400)
			return
		}
		conn, buffer, err := w.(http.Hijacker).Hijack()
		if err != nil {
			return
		}
		defer conn.Close()
		buffer.WriteString("HTTP/1.1 200 OK\r\n\r\nsecure")
		buffer.Flush()
	}))
	defer server.Close()
	cert := filepath.Join(t.TempDir(), "proxy-ca.pem")
	if err := os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("SSL_CERT_FILE", cert)
	ip, portText, err := net.SplitHostPort(server.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	port, err := strconv.Atoi(portText)
	if err != nil {
		t.Fatal(err)
	}
	p := endpoint{"https", ip, ip, port, "", ""}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	c, _, err := p.connect(ctx, protectedDial(testHooks{}), 1, "example.com:443")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	payload, err := io.ReadAll(c)
	if err != nil || string(payload) != "secure" {
		t.Fatalf("TLS CONNECT %q: %v", payload, err)
	}
	p.Host = "wrong.invalid"
	if bypass, _, err := p.connect(ctx, protectedDial(testHooks{}), 1, "example.com:443"); err == nil {
		bypass.Close()
		t.Fatal("accepted a proxy certificate for the wrong name")
	}
}

func TestSOCKS5CredentialsAndIPv6(t *testing.T) {
	ip, port, done := serveOnce(t, func(c net.Conn) error {
		greeting := make([]byte, 3)
		if _, err := io.ReadFull(c, greeting); err != nil || string(greeting) != string([]byte{5, 1, 2}) {
			return fmt.Errorf("bad SOCKS greeting: %v", err)
		}
		if _, err := c.Write([]byte{5, 2}); err != nil {
			return err
		}
		auth := make([]byte, 9)
		if _, err := io.ReadFull(c, auth); err != nil || string(auth) != "\x01\x03bob\x03pwd" {
			return fmt.Errorf("bad SOCKS auth: %v", err)
		}
		if _, err := c.Write([]byte{1, 0}); err != nil {
			return err
		}
		head := make([]byte, 4)
		if _, err := io.ReadFull(c, head); err != nil || string(head) != "\x05\x01\x00\x04" {
			return fmt.Errorf("bad SOCKS CONNECT: %v", err)
		}
		address, err := readAddress(c, head[3])
		if err != nil || address != "[2001:db8::2]:443" {
			return fmt.Errorf("bad SOCKS target %q: %v", address, err)
		}
		_, err = c.Write([]byte{5, 0, 0, 1, 127, 0, 0, 1, 0, 80})
		return err
	})
	p := endpoint{"socks5", ip, ip, port, "bob", "pwd"}
	ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
	defer cancel()
	c, bound, err := p.connect(ctx, protectedDial(testHooks{}), 1, "[2001:db8::2]:443")
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
	if bound != "127.0.0.1:80" {
		t.Fatalf("incorrect bound address: %s", bound)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}

func TestTunRoutingAndTraffic(t *testing.T) {
	for _, route := range []string{"proxy", "block"} {
		t.Run(route, func(t *testing.T) {
			pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
			if err != nil {
				t.Fatal(err)
			}
			defer unix.Close(pair[0])
			dest := tcpip.AddrFrom4([4]byte{198, 51, 100, 7})
			peerFD, err := fdbased.Open(strconv.Itoa(pair[1]), mtu, 0)
			if err != nil {
				unix.Close(pair[1])
				t.Fatal(err)
			}
			peer := stack.New(stack.Options{
				NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
				TransportProtocols: []stack.TransportProtocolFactory{tcp.NewProtocol},
			})
			defer func() { peer.Close(); peer.Wait() }()
			if err := peer.CreateNIC(1, peerFD); err != nil {
				t.Fatal(err)
			}
			local := tcpip.AddrFrom4([4]byte{10, 99, 0, 1})
			if err := peer.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber,
				AddressWithPrefix: tcpip.AddressWithPrefix{Address: local, PrefixLen: 30}}, stack.AddressProperties{}); err != nil {
				t.Fatal(err)
			}
			peer.SetRouteTable([]tcpip.Route{{Destination: headerIPv4Default(), NIC: 1}})
			h := testHooks{route, make(chan string, 16)}
			host, port, done := serveOnce(t, func(c net.Conn) error {
				reader := bufio.NewReader(c)
				req, err := http.ReadRequest(reader)
				if err != nil {
					return err
				}
				if req.Method != "CONNECT" || req.Host != "198.51.100.7:8080" {
					return fmt.Errorf("bad target %s", req.Host)
				}
				if _, err := io.WriteString(c, "HTTP/1.1 200 OK\r\n\r\n"); err != nil {
					return err
				}
				n, err := io.CopyN(c, reader, 4)
				if n != 4 {
					return fmt.Errorf("echo bytes %d: %v", n, err)
				}
				return err
			})
			e, err := Start(pair[0], h, "http", host, host, port, "", "", false)
			if err != nil {
				t.Fatal(err)
			}
			defer e.Stop()
			ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
			defer cancel()
			c, err := gonet.DialContextTCP(ctx, peer, tcpip.FullAddress{NIC: 1, Addr: dest, Port: 8080}, ipv4.ProtocolNumber)
			if err != nil {
				t.Fatal(err)
			}
			defer c.Close()
			c.SetDeadline(time.Now().Add(4 * time.Second))
			opened := <-h.log
			if !strings.HasSuffix(opened, " "+route) {
				t.Fatalf("incorrect route: %s", opened)
			}
			if route == "block" {
				if msg := <-h.log; !strings.HasPrefix(msg, "blocked by application rule") {
					t.Fatalf("unexpected block result %s", msg)
				}
				return
			}
			if _, err := io.WriteString(c, "ping"); err != nil {
				t.Fatal(err)
			}
			var reply [4]byte
			if _, err := io.ReadFull(c, reply[:]); err != nil || string(reply[:]) != "ping" {
				t.Fatalf("TUN echo %q: %v", reply, err)
			}
			if err := <-done; err != nil {
				t.Fatal(err)
			}
			c.Close()
			e.Stop()
			var traffic bool
			for len(h.log) > 0 {
				if msg := <-h.log; msg == "traffic 4 4" {
					traffic = true
				}
			}
			if !traffic {
				t.Fatal("missing upload/download sample")
			}
		})
	}
}

func TestSOCKS5UDPRelay(t *testing.T) {
	relay, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	defer relay.Close()
	relay.SetDeadline(time.Now().Add(5 * time.Second))
	bound, err := encodeAddress(relay.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	const destination = "198.51.100.7:9999"
	target, err := encodeAddress(destination)
	if err != nil {
		t.Fatal(err)
	}
	host, port, controlDone := serveOnce(t, func(conn net.Conn) error {
		var greeting [3]byte
		if _, err := io.ReadFull(conn, greeting[:]); err != nil || greeting != [3]byte{5, 1, 0} {
			return fmt.Errorf("bad greeting %v: %v", greeting, err)
		}
		if _, err := conn.Write([]byte{5, 0}); err != nil {
			return err
		}
		var head [4]byte
		if _, err := io.ReadFull(conn, head[:]); err != nil || head != [4]byte{5, 3, 0, 1} {
			return fmt.Errorf("bad associate %v: %v", head, err)
		}
		if address, err := readAddress(conn, head[3]); err != nil || address != "0.0.0.0:0" {
			return fmt.Errorf("bad associate address %s: %v", address, err)
		}
		if _, err := conn.Write(append([]byte{5, 0, 0}, bound...)); err != nil {
			return err
		}
		_, err := io.Copy(io.Discard, conn)
		return err
	})
	relayDone := make(chan error, 1)
	go func() {
		var data [128]byte
		n, from, err := relay.ReadFromUDP(data[:])
		if err != nil {
			relayDone <- err
			return
		}
		header := append([]byte{0, 0, 0}, target...)
		if string(data[:n]) != string(header)+"ping" {
			relayDone <- fmt.Errorf("incorrect relay packet: %x", data[:n])
			return
		}
		_, err = relay.WriteToUDP(append(header, "pong"...), from)
		relayDone <- err
	}()
	pair, err := unix.Socketpair(unix.AF_UNIX, unix.SOCK_DGRAM, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(pair[0])
	peerFD, err := fdbased.Open(strconv.Itoa(pair[1]), mtu, 0)
	if err != nil {
		unix.Close(pair[1])
		t.Fatal(err)
	}
	peer := stack.New(stack.Options{
		NetworkProtocols:   []stack.NetworkProtocolFactory{ipv4.NewProtocol},
		TransportProtocols: []stack.TransportProtocolFactory{udp.NewProtocol},
	})
	defer func() { peer.Close(); peer.Wait() }()
	if err := peer.CreateNIC(1, peerFD); err != nil {
		t.Fatal(err)
	}
	source := tcpip.AddrFrom4([4]byte{10, 99, 0, 1})
	if err := peer.AddProtocolAddress(1, tcpip.ProtocolAddress{Protocol: ipv4.ProtocolNumber,
		AddressWithPrefix: tcpip.AddressWithPrefix{Address: source, PrefixLen: 30}}, stack.AddressProperties{}); err != nil {
		t.Fatal(err)
	}
	peer.SetRouteTable([]tcpip.Route{{Destination: headerIPv4Default(), NIC: 1}})
	h := testHooks{"proxy", make(chan string, 16)}
	e, err := Start(pair[0], h, "socks5", host, host, port, "", "", false)
	if err != nil {
		t.Fatal(err)
	}
	defer e.Stop()
	local := tcpip.FullAddress{NIC: 1, Addr: source}
	remote := tcpip.FullAddress{NIC: 1, Addr: tcpip.AddrFrom4([4]byte{198, 51, 100, 7}), Port: 9999}
	client, err := gonet.DialUDP(peer, &local, &remote, ipv4.ProtocolNumber)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	client.SetDeadline(time.Now().Add(5 * time.Second))
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatal(err)
	}
	var reply [8]byte
	if n, err := client.Read(reply[:]); err != nil || string(reply[:n]) != "pong" {
		t.Fatalf("UDP reply %q: %v", reply[:n], err)
	}
	if err := <-relayDone; err != nil {
		t.Fatal(err)
	}
	e.Stop()
	if err := <-controlDone; err != nil {
		t.Fatal(err)
	}
}

func headerIPv4Default() tcpip.Subnet {
	subnet, err := tcpip.NewSubnet(tcpip.AddrFrom4([4]byte{}), tcpip.MaskFromBytes([]byte{0, 0, 0, 0}))
	if err != nil {
		panic(err)
	}
	return subnet
}
