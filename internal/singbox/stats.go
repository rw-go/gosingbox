package singbox

import (
	"context"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

// Counter is a single stat counter from QueryStats.
type Counter struct {
	Name  string
	Value int64
}

// SysStats mirrors sing-box GetSysStats response. Field tags match the
// panel contract (camelCase), which the Node.js version reproduces.
type SysStats struct {
	NumGoroutine uint32 `json:"numGoroutine"`
	NumGC        uint32 `json:"numGC"`
	Alloc        uint64 `json:"alloc"`
	TotalAlloc   uint64 `json:"totalAlloc"`
	Sys          uint64 `json:"sys"`
	Mallocs      uint64 `json:"mallocs"`
	Frees        uint64 `json:"frees"`
	LiveObjects  uint64 `json:"liveObjects"`
	PauseTotalNs uint64 `json:"pauseTotalNs"`
	Uptime       uint32 `json:"uptime"`
}

// statsClient talks to sing-box's v2ray_api StatsService over gRPC.
// The service name is overridden by sing-box to
// "v2ray.core.app.stats.command.StatsService".
type statsClient struct {
	addr string
	conn *grpc.ClientConn
	svc  statsServiceClient
}

type statsServiceClient interface {
	QueryStats(ctx context.Context, req *queryStatsRequest) (*queryStatsResponse, error)
	GetSysStats(ctx context.Context) (*SysStats, error)
}

type queryStatsRequest struct {
	Patterns []string
	Reset    bool
}

type queryStatsResponse struct {
	Stat []Counter
}

// newStatsClient dials the sing-box stats gRPC endpoint.
func newStatsClient(addr string) (*statsClient, error) {
	conn, err := grpc.NewClient(addr,
		grpc.WithTransportCredentials(insecure.NewCredentials()),
	)
	if err != nil {
		return nil, err
	}
	return &statsClient{addr: addr, conn: conn, svc: newStatsServiceClient(conn)}, nil
}

func (c *statsClient) Close() error {
	if c.conn != nil {
		return c.conn.Close()
	}
	return nil
}

// QueryStats queries counters matching any of the patterns.
func (c *statsClient) QueryStats(ctx context.Context, patterns []string, reset bool) ([]Counter, error) {
	resp, err := c.svc.QueryStats(ctx, &queryStatsRequest{Patterns: patterns, Reset: reset})
	if err != nil {
		return nil, err
	}
	return resp.Stat, nil
}

// GetSysStats returns sing-box process stats.
func (c *statsClient) GetSysStats(ctx context.Context) (*SysStats, error) {
	return c.svc.GetSysStats(ctx)
}

// StatsClient is the public interface for querying sing-box v2ray_api stats.
type StatsClient interface {
	QueryStats(ctx context.Context, patterns []string, reset bool) ([]Counter, error)
	GetSysStats(ctx context.Context) (*SysStats, error)
	Close() error
}

// NewStatsClientForTest dials the sing-box stats gRPC endpoint and returns a
// public client (used by the CLI driver; package-internal code can also use it).
func NewStatsClientForTest(addr string) (StatsClient, error) {
	c, err := newStatsClient(addr)
	if err != nil {
		return nil, err
	}
	return c, nil
}

// Ping performs a lightweight health check via GetSysStats.
func (p *Process) Ping(ctx context.Context) bool { return p.ping(ctx) }

// QueryUserStats queries per-user traffic counters (patterns ["user>>>"]).
func (p *Process) QueryUserStats(ctx context.Context, reset bool) ([]Counter, error) {
	return p.Query(ctx, []string{"user>>>"}, reset)
}

// Query runs QueryStats with the given patterns.
func (p *Process) Query(ctx context.Context, patterns []string, reset bool) ([]Counter, error) {
	c, err := newStatsClient(p.statsAddr)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return c.QueryStats(ctx, patterns, reset)
}

// Stats is a direct query helper without a running process reference.
func (p *Process) Stats(ctx context.Context) (*SysStats, error) {
	c, err := newStatsClient(p.statsAddr)
	if err != nil {
		return nil, err
	}
	defer c.Close()
	return c.GetSysStats(ctx)
}
func (p *Process) ping(ctx context.Context) bool {
	c, err := newStatsClient(p.statsAddr)
	if err != nil {
		return false
	}
	defer c.Close()
	_, err = c.GetSysStats(ctx)
	return err == nil
}

var _ = time.Second // keep import if unused in future edits
