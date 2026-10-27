package minibox

import (
	"context"

	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/boxnet/protocol/anytls"
	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/boxnet/protocol/direct"
	boxHTTP "github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/boxnet/protocol/http"
	upstreamSS "github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/boxnet/protocol/shadowsocks"
	upstreamSnell "github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/boxnet/protocol/snell"
	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/boxnet/protocol/socks"
	upstreamVLESS "github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/boxnet/protocol/vless"
	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/adapter/certificate"
	"github.com/sagernet/sing-box/adapter/endpoint"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/adapter/outbound"
	boxService "github.com/sagernet/sing-box/adapter/service"
	"github.com/sagernet/sing-box/dns"
	dnsTransport "github.com/sagernet/sing-box/dns/transport"
	dnsHosts "github.com/sagernet/sing-box/dns/transport/hosts"
	dnsLocal "github.com/sagernet/sing-box/dns/transport/local"
	dnsQUIC "github.com/sagernet/sing-box/dns/transport/quic"
	"github.com/sagernet/sing-box/protocol/block"
	outboundDNS "github.com/sagernet/sing-box/protocol/dns"
	upstreamHY2 "github.com/sagernet/sing-box/protocol/hysteria2"
	"github.com/sagernet/sing-box/protocol/wireguard"
	"github.com/sagernet/sing/common/ntp"
	singService "github.com/sagernet/sing/service"

	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/dnsgroup"
	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/protocol/familyselector"
	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/protocol/hysteria2"
	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/protocol/mieru"
	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/protocol/shadowsocks"
	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/protocol/snell"
	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/protocol/sourceprefix"
	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/protocol/userselector"
	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/protocol/vpngatepool"
	"github.com/OboardProject/oboard-agent/kernel/oboard-sb/internal/protocol/vless"
)

// SupportedProtocols is the intentionally small protocol surface exposed by the
// OBoard sing-box kernel. Do not add protocols here unless the Controller can
// generate, validate, audit, and subscribe them.
var SupportedProtocols = []string{"vless", "hysteria2", "anytls", "shadowsocks", "mieru", "snell", "socks", "http", "wireguard", "source-prefix", "family-selector", "user-selector", "vpngate-pool"}

// Context returns a sing-box context with only the inbounds/outbounds that
// OBoard supports in the first kernel line: VLESS, HY2, AnyTLS, and SS.
//
// This mirrors the mini-sb-agent optimisation approach: instead of importing
// sing-box's full command and default registry, we construct a minimal registry.
func Context(parent context.Context, clocks ...*RuntimeClock) context.Context {
	inbounds := inbound.NewRegistry()
	vless.RegisterInbound(inbounds)
	hysteria2.RegisterInbound(inbounds)
	anytls.RegisterInbound(inbounds)
	shadowsocks.RegisterInbound(inbounds)
	mieru.RegisterInbound(inbounds)
	snell.RegisterInbound(inbounds)
	socks.RegisterInbound(inbounds)

	outbounds := outbound.NewRegistry()
	direct.RegisterOutbound(outbounds)
	block.RegisterOutbound(outbounds)
	outboundDNS.RegisterOutbound(outbounds)
	upstreamVLESS.RegisterOutbound(outbounds)
	upstreamHY2.RegisterOutbound(outbounds)
	anytls.RegisterOutbound(outbounds)
	upstreamSS.RegisterOutbound(outbounds)
	mieru.RegisterOutbound(outbounds)
	upstreamSnell.RegisterOutbound(outbounds)
	sourceprefix.RegisterOutbound(outbounds)
	familyselector.RegisterOutbound(outbounds)
	userselector.RegisterOutbound(outbounds)
	vpngatepool.RegisterOutbound(outbounds)
	socks.RegisterOutbound(outbounds)
	boxHTTP.RegisterOutbound(outbounds)

	endpoints := endpoint.NewRegistry()
	wireguard.RegisterEndpoint(endpoints)

	dnsTransports := dns.NewTransportRegistry()
	dnsTransport.RegisterUDP(dnsTransports)
	dnsTransport.RegisterTCP(dnsTransports)
	dnsTransport.RegisterTLS(dnsTransports)
	dnsTransport.RegisterHTTPS(dnsTransports)
	dnsQUIC.RegisterTransport(dnsTransports)
	dnsgroup.Register(dnsTransports)
	dnsLocal.RegisterTransport(dnsTransports)
	dnsHosts.RegisterTransport(dnsTransports)

	ctx := box.Context(parent, inbounds, outbounds, endpoints, dnsTransports, boxService.NewRegistry(), certificate.NewRegistry())
	clock := NewRuntimeClock()
	if len(clocks) > 0 && clocks[0] != nil {
		clock = clocks[0]
	}
	singService.MustRegister[ntp.TimeService](ctx, clock)
	return ctx
}
