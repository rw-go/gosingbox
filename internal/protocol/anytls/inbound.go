// Derived from sing-box fork v1.14.3-updatable.1; see PROVENANCE.md.
package anytls

import (
	"context"
	"net"
	"strings"

	"github.com/sagernet/sing-box/adapter"
	"github.com/sagernet/sing-box/adapter/inbound"
	"github.com/sagernet/sing-box/common/listener"
	"github.com/sagernet/sing-box/common/tls"
	"github.com/sagernet/sing-box/common/uot"
	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/log"
	"github.com/sagernet/sing-box/option"
	"github.com/sagernet/sing/common"
	"github.com/sagernet/sing/common/auth"
	E "github.com/sagernet/sing/common/exceptions"
	"github.com/sagernet/sing/common/logger"
	M "github.com/sagernet/sing/common/metadata"
	N "github.com/sagernet/sing/common/network"

	anytls "github.com/anytls/sing-anytls"
	"github.com/anytls/sing-anytls/padding"
)

func RegisterInbound(registry *inbound.Registry) {
	// Each engine configuration gets its own registry and listener groups.
	// Nothing is shared with another engine or a rollback configuration.
	groups := &listenerGroups{groups: make(map[string]*sharedListener)}
	inbound.Register[Options](registry, C.TypeAnyTLS, func(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options Options) (adapter.Inbound, error) {
		return newInbound(ctx, router, logger, tag, options, groups)
	})
}

// Options adds an opt-in node extension. Members of a shared_listener use the
// same listen options and distinct tls.server_name values. Each member retains
// its own users, tag, certificate and AnyTLS service.
type Options struct {
	option.AnyTLSInboundOptions
	SharedListener string `json:"shared_listener,omitempty"`
}

type Inbound struct {
	inbound.Adapter
	tlsConfig     tls.ServerConfig
	router        adapter.ConnectionRouterEx
	logger        logger.ContextLogger
	listener      *listener.Listener
	service       *anytls.Service
	shared        *sharedListener
	listenOptions option.ListenOptions
}

func NewInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options option.AnyTLSInboundOptions) (adapter.Inbound, error) {
	return newInbound(ctx, router, logger, tag, Options{AnyTLSInboundOptions: options}, nil)
}

func newInbound(ctx context.Context, router adapter.Router, logger log.ContextLogger, tag string, options Options, groups *listenerGroups) (adapter.Inbound, error) {
	if options.TLS == nil || !options.TLS.Enabled {
		return nil, E.New("managed AnyTLS requires TLS")
	}
	if options.TLS.Reality != nil && options.TLS.Reality.Enabled {
		return nil, E.New("managed AnyTLS requires ordinary TLS; Reality is not supported")
	}
	inbound := &Inbound{
		Adapter:       inbound.NewAdapter(C.TypeAnyTLS, tag),
		router:        uot.NewRouter(router, logger),
		logger:        logger,
		listenOptions: options.ListenOptions,
	}

	if options.TLS != nil && options.TLS.Enabled {
		tlsConfig, err := tls.NewServer(ctx, logger, common.PtrValueOrDefault(options.TLS))
		if err != nil {
			return nil, err
		}
		inbound.tlsConfig = tlsConfig
	}

	paddingScheme := padding.DefaultPaddingScheme
	if len(options.PaddingScheme) > 0 {
		paddingScheme = []byte(strings.Join(options.PaddingScheme, "\n"))
	}

	service, err := anytls.NewService(anytls.ServiceConfig{
		Users: common.Map(options.Users, func(it option.AnyTLSUser) anytls.User {
			return anytls.User(it)
		}),
		PaddingScheme: paddingScheme,
		Handler:       (*inboundHandler)(inbound),
		Logger:        logger,
	})
	if err != nil {
		return nil, err
	}
	inbound.service = service
	listenOptions := listener.Options{
		Context:           ctx,
		Logger:            logger,
		Network:           []string{N.NetworkTCP},
		Listen:            options.ListenOptions,
		ConnectionHandler: inbound,
	}
	if options.SharedListener != "" {
		shared, err := groups.join(options.SharedListener, options.TLS.ServerName, inbound, listenOptions)
		if err != nil {
			_ = service.Close()
			return nil, err
		}
		inbound.shared = shared
	} else {
		inbound.listener = listener.New(listenOptions)
	}
	return inbound, nil
}

func (h *Inbound) Start(stage adapter.StartStage, scope *adapter.Scope) error {
	if stage != adapter.StartStateStart {
		return nil
	}
	if h.tlsConfig != nil {
		err := h.tlsConfig.Start()
		if err != nil {
			return err
		}
		scope.Add(h.tlsConfig.Close)
	}
	scope.Add(h.service.Close)
	if h.shared != nil {
		scope.Add(h.shared.Close)
		return h.shared.startMember()
	}
	err := h.listener.Start()
	if err != nil {
		return err
	}
	scope.Add(h.listener.Close)
	return nil
}

func (h *Inbound) NewConnection(ctx context.Context, conn net.Conn, metadata adapter.InboundContext, onClose N.CloseHandlerFunc) {
	if h.tlsConfig != nil {
		tlsConn, err := tls.ServerHandshake(ctx, conn, h.tlsConfig)
		if err != nil {
			N.CloseOnHandshakeFailure(conn, onClose, err)
			h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source, ": TLS handshake"))
			return
		}
		conn = tlsConn
	}
	err := h.service.NewConnection(adapter.WithContext(ctx, &metadata), conn, metadata.Source, onClose)
	if err != nil {
		N.CloseOnHandshakeFailure(conn, onClose, err)
		h.logger.ErrorContext(ctx, E.Cause(err, "process connection from ", metadata.Source))
	}
}

type inboundHandler Inbound

func (h *inboundHandler) NewConnectionEx(ctx context.Context, conn net.Conn, source M.Socksaddr, destination M.Socksaddr, onClose N.CloseHandlerFunc) {
	var metadata adapter.InboundContext
	metadata.Inbound = h.Tag()
	metadata.InboundType = h.Type()
	//nolint:staticcheck
	metadata.InboundDetour = h.listenOptions.Detour
	//nolint:staticcheck
	metadata.Source = source
	metadata.Destination = destination.Unwrap()
	if userName, _ := auth.UserFromContext[string](ctx); userName != "" {
		metadata.User = userName
		h.logger.InfoContext(ctx, "[", userName, "] inbound connection to ", metadata.Destination)
	} else {
		h.logger.InfoContext(ctx, "inbound connection to ", metadata.Destination)
	}
	h.router.RouteConnectionEx(ctx, conn, metadata, onClose)
}

var _ adapter.UpdatableInbound[option.AnyTLSUser] = (*Inbound)(nil)

func (h *Inbound) UpdateUsers(users []option.AnyTLSUser) error {
	h.service.UpdateUsers(common.Map(users, func(user option.AnyTLSUser) anytls.User { return anytls.User(user) }))
	return nil
}
