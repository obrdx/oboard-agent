// SPDX-License-Identifier: GPL-3.0-or-later
// Derived from sing-box v1.14.4; see internal/boxnet/UPSTREAM.

package socks

import (
	"context"
	"net"

	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/boxnet/common/dialer"
	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/buf"
	"github.com/sagernet/sing/common/bufio"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/common/uot"
	"github.com/sagernet/sing/protocol/socks"
	"github.com/sagernet/sing/service"
)

// OutboundOptions extends sing-box's SOCKS outbound options with an explicit
// remote_dns switch. When omitted or true, SOCKS5 and SOCKS4a send domain
// destinations to the proxy (SOCKS5h / remote DNS). Setting remote_dns=false
// resolves domain destinations locally before dialing the SOCKS server.
type OutboundOptions struct {
	option.SOCKSOutboundOptions
	RemoteDNS *bool `json:"remote_dns,omitempty"`
}

func RegisterOutbound(registry *outbound.Registry) {
	outbound.Register[OutboundOptions](registry, C.TypeSOCKS, NewOutbound)
}

var _ adapter.Outbound = (*Outbound)(nil)

type Outbound struct {
	outbound.Adapter
	dnsRouter adapter.DNSRouter
	logger    logger.ContextLogger
	client    *socks.Client
	resolve   bool
	uotClient *uot.Client
}

func NewOutbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options OutboundOptions) (adapter.Outbound, error) {
	var version socks.Version
	var err error
	if options.Version != "" {
		version, err = socks.ParseVersion(options.Version)
	} else {
		version = socks.Version5
	}
	if err != nil {
		return nil, err
	}
	resolve := version == socks.Version4
	if options.RemoteDNS != nil {
		if version == socks.Version4 && *options.RemoteDNS {
			return nil, E.New("socks4 does not support remote_dns")
		}
		if version != socks.Version4 {
			resolve = !*options.RemoteDNS
		}
	}
	outboundDialer, err := dialer.New(ctx, options.DialerOptions, options.ServerIsDomain())
	if err != nil {
		return nil, err
	}
	outbound := &Outbound{
		Adapter:   outbound.NewAdapterWithDialerOptions(C.TypeSOCKS, tag, options.Network.Build(), options.DialerOptions),
		dnsRouter: service.FromContext[adapter.DNSRouter](ctx),
		logger:    logger,
		client:    socks.NewClient(outboundDialer, options.ServerOptions.Build(), version, options.Username, options.Password),
		resolve:   resolve,
	}
	uotOptions := common.PtrValueOrDefault(options.UDPOverTCP)
	if uotOptions.Enabled {
		outbound.uotClient = &uot.Client{
			Dialer:  outbound.client,
			Version: uotOptions.Version,
		}
	}
	return outbound, nil
}

func (h *Outbound) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	switch N.NetworkName(network) {
	case N.NetworkTCP:
		h.logger.InfoContext(ctx, "outbound connection to ", destination)
	case N.NetworkUDP:
		if h.uotClient != nil {
			h.logger.InfoContext(ctx, "outbound UoT connect packet connection to ", destination)
			if h.resolve && destination.IsDomain() {
				destinationAddresses, err := h.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
				if err != nil {
					return nil, err
				}
				return N.DialSerial(ctx, h.uotClient, network, destination, destinationAddresses)
			}
			return h.uotClient.DialContext(ctx, network, destination)
		}
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	default:
		return nil, E.Extend(N.ErrUnknownNetwork, network)
	}
	if h.resolve && destination.IsDomain() {
		destinationAddresses, err := h.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
		if err != nil {
			return nil, err
		}
		return N.DialSerial(ctx, h.client, network, destination, destinationAddresses)
	}
	return h.client.DialContext(ctx, network, destination)
}

func (h *Outbound) ListenPacket(ctx context.Context, destination M.Socksaddr) (net.PacketConn, error) {
	ctx, metadata := adapter.ExtendContext(ctx)
	metadata.Outbound = h.Tag()
	metadata.Destination = destination
	if h.uotClient != nil {
		h.logger.InfoContext(ctx, "outbound UoT packet connection to ", destination)
		if h.resolve {
			if destination.IsDomain() {
				destinationAddresses, err := h.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
				if err != nil {
					return nil, err
				}
				packetConn, _, err := N.ListenSerial(ctx, h.uotClient, destination, destinationAddresses)
				if err != nil {
					return nil, err
				}
				return newResolvePacketConn(ctx, h.dnsRouter, packetConn), nil
			}
			packetConn, err := h.uotClient.ListenPacket(ctx, destination)
			if err != nil {
				return nil, err
			}
			return newResolvePacketConn(ctx, h.dnsRouter, packetConn), nil
		}
		return h.uotClient.ListenPacket(ctx, destination)
	}
	if h.resolve {
		if destination.IsDomain() {
			destinationAddresses, err := h.dnsRouter.Lookup(ctx, destination.Fqdn, adapter.DNSQueryOptions{})
			if err != nil {
				return nil, err
			}
			packetConn, _, err := N.ListenSerial(ctx, h.client, destination, destinationAddresses)
			if err != nil {
				return nil, err
			}
			return newResolvePacketConn(ctx, h.dnsRouter, packetConn), nil
		}
		h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
		packetConn, err := h.client.ListenPacket(ctx, destination)
		if err != nil {
			return nil, err
		}
		return newResolvePacketConn(ctx, h.dnsRouter, packetConn), nil
	}
	h.logger.InfoContext(ctx, "outbound packet connection to ", destination)
	return h.client.ListenPacket(ctx, destination)
}

type resolvePacketConn struct {
	net.PacketConn
	packetConn N.PacketConn
	ctx        context.Context
	dnsRouter  adapter.DNSRouter
}

func newResolvePacketConn(ctx context.Context, dnsRouter adapter.DNSRouter, conn net.PacketConn) *resolvePacketConn {
	return &resolvePacketConn{
		PacketConn: conn,
		packetConn: bufio.NewPacketConn(conn),
		ctx:        ctx,
		dnsRouter:  dnsRouter,
	}
}

func (c *resolvePacketConn) resolveDestination(destination M.Socksaddr) (M.Socksaddr, error) {
	if !destination.IsDomain() {
		return destination, nil
	}
	lookupCtx, cancel := context.WithTimeout(c.ctx, C.DNSTimeout)
	defer cancel()
	addresses, err := c.dnsRouter.Lookup(lookupCtx, destination.Fqdn, adapter.DNSQueryOptions{})
	if err != nil {
		return M.Socksaddr{}, err
	}
	if len(addresses) == 0 {
		return M.Socksaddr{}, E.New("empty dns response for ", destination.Fqdn)
	}
	return M.SocksaddrFrom(addresses[0], destination.Port), nil
}

func (c *resolvePacketConn) ReadPacket(buffer *buf.Buffer) (M.Socksaddr, error) {
	return c.packetConn.ReadPacket(buffer)
}

func (c *resolvePacketConn) WritePacket(buffer *buf.Buffer, destination M.Socksaddr) error {
	resolved, err := c.resolveDestination(destination)
	if err != nil {
		buffer.Release()
		return err
	}
	return c.packetConn.WritePacket(buffer, resolved)
}

func (c *resolvePacketConn) WriteTo(p []byte, addr net.Addr) (int, error) {
	destination := M.SocksaddrFromNet(addr)
	if destination.IsDomain() {
		resolved, err := c.resolveDestination(destination)
		if err != nil {
			return 0, err
		}
		addr = resolved.UDPAddr()
	}
	return c.PacketConn.WriteTo(p, addr)
}

func (c *resolvePacketConn) FrontHeadroom() int {
	return N.CalculateFrontHeadroom(c.packetConn)
}

func (c *resolvePacketConn) Upstream() any {
	return c.PacketConn
}
