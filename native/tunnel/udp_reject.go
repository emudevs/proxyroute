package tunnel

import (
	"errors"

	"gvisor.dev/gvisor/pkg/tcpip/adapters/gonet"
	"gvisor.dev/gvisor/pkg/tcpip/header"
	"gvisor.dev/gvisor/pkg/tcpip/stack"
	"gvisor.dev/gvisor/pkg/tcpip/transport/udp"
	"gvisor.dev/gvisor/pkg/waiter"
)

// core.CreateStack attaches the link while it is assembling the stack. Delay
// packet delivery until the UDP handler and routes have been initialized.
type delayedLink struct {
	stack.LinkEndpoint
	dispatcher stack.NetworkDispatcher
	active     bool
}

func (l *delayedLink) Attach(dispatcher stack.NetworkDispatcher) {
	if l.active {
		l.LinkEndpoint.Attach(dispatcher)
		return
	}
	l.dispatcher = dispatcher
}

func (l *delayedLink) activate() {
	l.active = true
	l.LinkEndpoint.Attach(l.dispatcher)
	l.dispatcher = nil
}

func installUDPHandler(e *Engine) {
	s := e.stack
	v4, _ := s.NetworkProtocolInstance(header.IPv4ProtocolNumber).(stack.RejectIPv4WithHandler)
	v6, _ := s.NetworkProtocolInstance(header.IPv6ProtocolNumber).(stack.RejectIPv6WithHandler)
	// The forwarder callback is synchronous. Use a per-packet callback to keep
	// ownership of the first packet associated with this specific UDP flow.
	s.SetTransportProtocolHandler(udp.ProtocolNumber, func(id stack.TransportEndpointID, pkt *stack.PacketBuffer) bool {
		f := udp.NewForwarder(s, func(request *udp.ForwarderRequest) {
			queue := new(waiter.Queue)
			endpoint, err := request.CreateEndpoint(queue)
			if err != nil {
				return
			}
			conn := gonet.NewUDPConn(queue, endpoint)
			if e.proxy.Protocol == "direct" {
				e.launch(conn, &id, 17)
				return
			}
			retained := pkt.Clone()
			e.launchUDP(conn, &id, retained.DecRef, func(err error) {
				if !errors.Is(err, errUDPUnsupported) && !errors.Is(err, errIPv6Unavailable) &&
					!errors.Is(err, errQUICUnavailable) && !errors.Is(err, errUDPNoResponse) {
					return
				}
				switch retained.NetworkProtocolNumber {
				case header.IPv4ProtocolNumber:
					if v4 != nil {
						_ = v4.SendRejectionError(retained, stack.RejectIPv4WithICMPPortUnreachable, true)
					}
				case header.IPv6ProtocolNumber:
					if v6 != nil {
						_ = v6.SendRejectionError(retained, stack.RejectIPv6WithICMPPortUnreachable, true)
					}
				}
			})
		})
		return f.HandlePacket(id, pkt)
	})
}
