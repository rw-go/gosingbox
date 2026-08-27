package singbox

import (
	"context"
	"encoding/binary"

	"google.golang.org/grpc"
)

// Minimal client for sing-box's v2ray_api StatsService.
//
// sing-box overrides the gRPC service name to
// "v2ray.core.app.stats.command.StatsService" and only implements:
//   GetStats / QueryStats / GetSysStats
//
// We implement the wire protocol by hand (no generated stubs) to keep the
// module dependency-light and stable across sing-box 1.12.x.

const (
	statsServiceName  = "/v2ray.core.app.stats.command.StatsService/"
	queryStatsMethod  = statsServiceName + "QueryStats"
	getSysStatsMethod = statsServiceName + "GetSysStats"
)

// grpcStatsServiceClient is a concrete statsServiceClient via raw gRPC invoke.
type grpcStatsServiceClient struct {
	cc *grpc.ClientConn
}

func newStatsServiceClient(cc *grpc.ClientConn) statsServiceClient {
	return &grpcStatsServiceClient{cc: cc}
}

// --- wire types ---

type wireQueryStatsRequest struct {
	Pattern  string
	Reset    bool
	Patterns []string
	Regexp   bool
}

func (r *wireQueryStatsRequest) marshal() []byte {
	buf := []byte{}
	if r.Pattern != "" {
		buf = appendTag(buf, 1, wireBytes)
		buf = appendVarint(buf, uint64(len(r.Pattern)))
		buf = append(buf, r.Pattern...)
	}
	if r.Reset {
		buf = appendTag(buf, 2, wireVarint)
		buf = appendVarint(buf, 1)
	}
	for _, p := range r.Patterns {
		buf = appendTag(buf, 3, wireBytes)
		buf = appendVarint(buf, uint64(len(p)))
		buf = append(buf, p...)
	}
	if r.Regexp {
		buf = appendTag(buf, 4, wireVarint)
		buf = appendVarint(buf, 1)
	}
	return buf
}

type wireStat struct {
	Name  string
	Value int64
}

type wireQueryStatsResponse struct {
	Stat []wireStat
}

func (r *wireQueryStatsResponse) unmarshal(data []byte) error {
	r.Stat = nil
	for len(data) > 0 {
		tag, n := readVarint(data)
		data = data[n:]
		fieldNum := int(tag >> 3)
		wireType := int(tag & 7)
		switch fieldNum {
		case 1:
			// Stat (message)
			l, m := readVarint(data)
			data = data[m:]
			if int(l) > len(data) {
				return errShortBuffer
			}
			msgData := data[:l]
			data = data[l:]
			var st wireStat
			if err := st.unmarshal(msgData); err != nil {
				return err
			}
			r.Stat = append(r.Stat, st)
		default:
			// skip field
			if err := skipField(data, wireType); err != nil {
				return err
			}
		}
	}
	return nil
}

func (s *wireStat) unmarshal(data []byte) error {
	for len(data) > 0 {
		tag, n := readVarint(data)
		data = data[n:]
		fieldNum := int(tag >> 3)
		wireType := int(tag & 7)
		switch fieldNum {
		case 1:
			l, m := readVarint(data)
			data = data[m:]
			if int(l) > len(data) {
				return errShortBuffer
			}
			s.Name = string(data[:l])
			data = data[l:]
		case 2:
			v, m := readVarint(data)
			data = data[m:]
			_ = wireType
			s.Value = int64(v)
		default:
			if err := skipField(data, wireType); err != nil {
				return err
			}
		}
	}
	return nil
}

type wireGetSysStatsResponse struct {
	NumGoroutine uint32
	NumGC        uint32
	Alloc        uint64
	TotalAlloc   uint64
	Sys          uint64
	Mallocs      uint64
	Frees        uint64
	LiveObjects  uint64
	PauseTotalNs uint64
	Uptime       uint32
}

func (r *wireGetSysStatsResponse) unmarshal(data []byte) error {
	for len(data) > 0 {
		tag, n := readVarint(data)
		data = data[n:]
		fieldNum := int(tag >> 3)
		wireType := int(tag & 7)
		if wireType != wireVarint {
			if err := skipField(data, wireType); err != nil {
				return err
			}
			continue
		}
		v, m := readVarint(data)
		data = data[m:]
		switch fieldNum {
		case 1:
			r.NumGoroutine = uint32(v)
		case 2:
			r.NumGC = uint32(v)
		case 3:
			r.Alloc = v
		case 4:
			r.TotalAlloc = v
		case 5:
			r.Sys = v
		case 6:
			r.Mallocs = v
		case 7:
			r.Frees = v
		case 8:
			r.LiveObjects = v
		case 9:
			r.PauseTotalNs = v
		case 10:
			r.Uptime = uint32(v)
		}
	}
	return nil
}

func (c *grpcStatsServiceClient) QueryStats(ctx context.Context, req *queryStatsRequest) (*queryStatsResponse, error) {
	wire := &wireQueryStatsRequest{
		Reset:    req.Reset,
		Patterns: req.Patterns,
	}
	raw, err := c.invoke(ctx, queryStatsMethod, wire.marshal())
	if err != nil {
		return nil, err
	}
	var resp wireQueryStatsResponse
	if err := resp.unmarshal(raw); err != nil {
		return nil, err
	}
	out := &queryStatsResponse{}
	for _, st := range resp.Stat {
		out.Stat = append(out.Stat, Counter{Name: st.Name, Value: st.Value})
	}
	return out, nil
}

func (c *grpcStatsServiceClient) GetSysStats(ctx context.Context) (*SysStats, error) {
	raw, err := c.invoke(ctx, getSysStatsMethod, nil)
	if err != nil {
		return nil, err
	}
	var resp wireGetSysStatsResponse
	if err := resp.unmarshal(raw); err != nil {
		return nil, err
	}
	return &SysStats{
		NumGoroutine: resp.NumGoroutine,
		NumGC:        resp.NumGC,
		Alloc:        resp.Alloc,
		TotalAlloc:   resp.TotalAlloc,
		Sys:          resp.Sys,
		Mallocs:      resp.Mallocs,
		Frees:        resp.Frees,
		LiveObjects:  resp.LiveObjects,
		PauseTotalNs: resp.PauseTotalNs,
		Uptime:       resp.Uptime,
	}, nil
}

func (c *grpcStatsServiceClient) invoke(ctx context.Context, method string, body []byte) ([]byte, error) {
	in := &rawBytes{b: body}
	out := &rawBytes{}
	if err := c.cc.Invoke(ctx, method, in, out, grpc.ForceCodec(rawCodec{})); err != nil {
		return nil, err
	}
	return out.b, nil
}

// rawBytes adapts a raw payload for grpc with a raw codec (no proto.Message
// requirement).
type rawBytes struct {
	b []byte
}

func (r *rawBytes) Reset()         {}
func (r *rawBytes) String() string { return string(r.b) }

// rawCodec marshals rawBytes as-is (protobuf wire bytes already encoded).
type rawCodec struct{}

func (rawCodec) Name() string { return "proto" }
func (rawCodec) Marshal(v any) ([]byte, error) {
	if r, ok := v.(*rawBytes); ok {
		return r.b, nil
	}
	return nil, errShort("rawCodec: unexpected type")
}
func (rawCodec) Unmarshal(data []byte, v any) error {
	if r, ok := v.(*rawBytes); ok {
		r.b = data
		return nil
	}
	return errShort("rawCodec: unexpected type")
}

// --- protobuf wire helpers ---

const (
	wireVarint = 0
	wireBytes  = 2
)

var errShortBuffer = errShort("short buffer")

type errShort string

func (e errShort) Error() string { return string(e) }

func appendVarint(buf []byte, v uint64) []byte {
	var tmp [10]byte
	n := binary.PutUvarint(tmp[:], v)
	return append(buf, tmp[:n]...)
}

func appendTag(buf []byte, fieldNum int, wireType int) []byte {
	return appendVarint(buf, uint64(fieldNum)<<3|uint64(wireType))
}

func readVarint(data []byte) (uint64, int) {
	var v uint64
	var shift uint
	for i, b := range data {
		v |= uint64(b&0x7f) << shift
		if b < 0x80 {
			return v, i + 1
		}
		shift += 7
		if shift >= 64 {
			break
		}
	}
	return 0, len(data)
}

func skipField(data []byte, wireType int) error {
	switch wireType {
	case wireVarint:
		_, n := readVarint(data)
		if n == 0 {
			return errShortBuffer
		}
		return nil
	case wireBytes:
		l, m := readVarint(data)
		if m == 0 || int(l) > len(data)-m {
			return errShortBuffer
		}
		return nil
	default:
		return errShort("unsupported wire type")
	}
}
