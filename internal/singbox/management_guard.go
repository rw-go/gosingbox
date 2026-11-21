package singbox

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"time"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/outbound"
	"github.com/sagernet/sing-box/common/dialer"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing-box/protocol/direct"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"
	"github.com/sagernet/sing/service"
)

// Install the guard on the actual direct dial, after profile routing and
// destination overrides. The node's own management clients use separate dialers.
func (e *Engine) protectDirectOutbounds(ctx context.Context, options *option.Options) error {
	stats, err := netip.ParseAddrPort(e.statsAddr)
	if err != nil {
		return fmt.Errorf("invalid stats listener: %w", err)
	}
	clash, err := netip.ParseAddrPort(e.clashAddr)
	if err != nil {
		return fmt.Errorf("invalid clash listener: %w", err)
	}
	ports := [2]uint16{stats.Port(), clash.Port()}
	registry := service.FromContext[adapter.OutboundRegistry](ctx).(*outbound.Registry)
	outbound.Register(registry, C.TypeDirect, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, opts option.DirectOutboundOptions) (adapter.Outbound, error) {
		base, err := direct.NewOutbound(ctx, router, logger, tag, opts)
		if err != nil {
			return nil, err
		}
		return &guardedDirect{Outbound: base.(*direct.Outbound), ports: ports, ctx: ctx, options: opts}, nil
	})
	// The core constructs its implicit direct outbound outside the registry.
	if len(options.Outbounds) == 0 {
		options.Outbounds = []option.Outbound{{Type: C.TypeDirect, Tag: "direct", Options: &option.DirectOutboundOptions{}}}
	}
	return nil
}

type guardedDirect struct {
	*direct.Outbound
	ports   [2]uint16
	ctx     context.Context
	options option.DirectOutboundOptions
}

func (d *guardedDirect) protects(network string, port uint16) bool {
	return port != 0 && N.NetworkName(network) == N.NetworkTCP && (port == d.ports[0] || port == d.ports[1])
}

func checkManagementAddresses(destination M.Socksaddr, addresses []netip.Addr) error {
	if len(addresses) == 0 && destination.IsIP() {
		addresses = []netip.Addr{destination.Addr}
	}
	if len(addresses) == 0 {
		return fmt.Errorf("empty management-port destination")
	}
	for _, address := range addresses {
		ip := address.Unmap()
		if !ip.IsValid() || ip.IsLoopback() || ip.IsUnspecified() {
			return fmt.Errorf("node management destination is reserved")
		}
	}
	return nil
}

func (d *guardedDirect) DialContext(ctx context.Context, network string, destination M.Socksaddr) (net.Conn, error) {
	if !d.protects(network, destination.Port) {
		return d.Outbound.DialContext(ctx, network, destination)
	}
	if destination.IsIP() {
		if err := checkManagementAddresses(destination, nil); err != nil {
			return nil, err
		}
		return d.Outbound.DialContext(ctx, network, destination)
	}

	// Use the outbound's configured DNS and pass the checked addresses to the
	// dialer. Re-resolving the original name would invalidate this check.
	query, err := dialer.NewDNSQueryOptions(d.ctx, d.options.DomainResolver, false)
	if err != nil {
		return nil, err
	}
	resolverOptions := d.options.DomainResolver
	if d.options.DomainStrategy != 0 && (resolverOptions == nil || resolverOptions.Server == "" || resolverOptions.Strategy == 0) {
		query.Strategy = C.DomainStrategy(d.options.DomainStrategy)
	}
	resolver := service.FromContext[adapter.DNSRouter](d.ctx)
	addresses, err := resolver.Lookup(ctx, destination.Fqdn, query)
	if err != nil {
		return nil, err
	}
	return d.DialParallel(ctx, network, destination, addresses)
}

func (d *guardedDirect) DialParallel(ctx context.Context, network string, destination M.Socksaddr, addresses []netip.Addr) (net.Conn, error) {
	if d.protects(network, destination.Port) {
		if err := checkManagementAddresses(destination, addresses); err != nil {
			return nil, err
		}
	}
	return d.Outbound.DialParallel(ctx, network, destination, addresses)
}

func (d *guardedDirect) DialParallelNetwork(ctx context.Context, network string, destination M.Socksaddr, addresses []netip.Addr, strategy *C.NetworkStrategy, interfaces, fallback []C.InterfaceType, delay time.Duration) (net.Conn, error) {
	if d.protects(network, destination.Port) {
		if err := checkManagementAddresses(destination, addresses); err != nil {
			return nil, err
		}
	}
	return d.Outbound.DialParallelNetwork(ctx, network, destination, addresses, strategy, interfaces, fallback, delay)
}
