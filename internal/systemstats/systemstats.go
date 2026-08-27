// Package systemstats reads host system stats (/proc) for the panel's
// get-system-stats and start responses, mirroring the Node.js version's
// getSystemInfo()/getSystemStats() and NetworkStatsService.
package systemstats

import (
	"bufio"
	"os"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Info mirrors libs/contract NodeSystemInfoSchema.
type Info struct {
	Arch              string   `json:"arch"`
	Cpus              int      `json:"cpus"`
	CpuModel          string   `json:"cpuModel"`
	MemoryTotal       uint64   `json:"memoryTotal"`
	Hostname          string   `json:"hostname"`
	Platform          string   `json:"platform"`
	Release           string   `json:"release"`
	Type              string   `json:"type"`
	Version           string   `json:"version"`
	NetworkInterfaces []string `json:"networkInterfaces"`
}

// InterfaceRate mirrors libs/contract NetworkInterfaceSchema.
type InterfaceRate struct {
	Interface     string  `json:"interface"`
	RxBytesPerSec float64 `json:"rxBytesPerSec"`
	TxBytesPerSec float64 `json:"txBytesPerSec"`
	RxTotal       uint64  `json:"rxTotal"`
	TxTotal       uint64  `json:"txTotal"`
}

// Stats mirrors libs/contract NodeSystemStatsSchema.
type Stats struct {
	MemoryFree uint64         `json:"memoryFree"`
	MemoryUsed uint64         `json:"memoryUsed"`
	Uptime     float64        `json:"uptime"`
	LoadAvg    []float64      `json:"loadAvg"`
	Interface  *InterfaceRate `json:"interface"`
}

// System mirrors NodeSystemSchema (info + stats) used in the start response.
type System struct {
	Info  Info  `json:"info"`
	Stats Stats `json:"stats"`
}

// Reader gathers system + network stats.
type Reader struct {
	mu           sync.RWMutex
	hostname     string
	release      string
	cpuModel     string
	prev         map[string]ifaceCounters
	rates        map[string]*InterfaceRate
	defaultIface string
}

type ifaceCounters struct {
	rx, tx    uint64
	timestamp time.Time
}

// NewReader initializes the reader and starts polling (returns promptly).
func NewReader() *Reader {
	r := &Reader{
		hostname: readHostname(),
		release:  readKernelRelease(),
		cpuModel: readCPUModel(),
		prev:     map[string]ifaceCounters{},
		rates:    map[string]*InterfaceRate{},
	}
	r.readNetDev()
	r.defaultIface = r.resolveDefaultIface()

	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for range t.C {
			r.readNetDev()
		}
	}()
	return r
}

// Info returns a snapshot of node system info.
func (r *Reader) Info() Info {
	_, memTotal := memInfo()
	ifaces := r.networkInterfaceNames()
	return Info{
		Arch:              runtime.GOARCH,
		Cpus:              runtime.NumCPU(),
		CpuModel:          r.cpuModel,
		MemoryTotal:       memTotal,
		Hostname:          r.hostname,
		Platform:          "linux",
		Release:           r.release,
		Type:              "Linux",
		Version:           r.release,
		NetworkInterfaces: ifaces,
	}
}

// Stats returns a snapshot of node system stats.
func (r *Reader) Stats() Stats {
	memFree, memTotal := memInfo()
	return Stats{
		MemoryFree: memFree,
		MemoryUsed: memTotal - memFree,
		Uptime:     readUptime(),
		LoadAvg:    readLoadAvg(),
		Interface:  r.DefaultRate(),
	}
}

// System returns info + stats in one struct.
func (r *Reader) System() System {
	return System{Info: r.Info(), Stats: r.Stats()}
}

// DefaultRate returns the default interface rate (or nil).
func (r *Reader) DefaultRate() *InterfaceRate {
	r.mu.RLock()
	defer r.mu.RUnlock()
	if r.defaultIface == "" {
		return nil
	}
	return r.rates[r.defaultIface]
}

// networkInterfaceNames lists non-loopback network interfaces.
func (r *Reader) networkInterfaceNames() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	names := make([]string, 0, len(r.prev))
	for name := range r.prev {
		names = append(names, name)
	}
	return names
}

// readNetDev reads /proc/net/dev and updates per-interface counters/rates.
func (r *Reader) readNetDev() {
	data, err := os.ReadFile("/proc/net/dev")
	if err != nil {
		return
	}
	now := time.Now()
	next := map[string]ifaceCounters{}

	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := sc.Text()
		colon := strings.Index(line, ":")
		if colon == -1 {
			continue
		}
		name := strings.TrimSpace(line[:colon])
		if name == "lo" {
			continue
		}
		fields := strings.Fields(line[colon+1:])
		if len(fields) < 16 {
			continue
		}
		rx, err1 := strconv.ParseUint(fields[0], 10, 64)
		tx, err2 := strconv.ParseUint(fields[8], 10, 64)
		if err1 != nil || err2 != nil {
			continue
		}
		next[name] = ifaceCounters{rx: rx, tx: tx, timestamp: now}
	}

	r.mu.Lock()
	defer r.mu.Unlock()
	for name, cur := range next {
		prev, ok := r.prev[name]
		r.prev[name] = cur
		if !ok {
			continue
		}
		elapsed := cur.timestamp.Sub(prev.timestamp).Seconds()
		if elapsed <= 0 {
			continue
		}
		rxRate := float64(cur.rx-prev.rx) / elapsed
		txRate := float64(cur.tx-prev.tx) / elapsed
		r.rates[name] = &InterfaceRate{
			Interface:     name,
			RxBytesPerSec: max(rxRate, 0),
			TxBytesPerSec: max(txRate, 0),
			RxTotal:       cur.rx,
			TxTotal:       cur.tx,
		}
	}
}

// resolveDefaultIface reads /proc/net/route to find the lowest-metric
// default (destination 0.0.0.0) interface.
func (r *Reader) resolveDefaultIface() string {
	data, err := os.ReadFile("/proc/net/route")
	if err != nil {
		return ""
	}
	best := ""
	bestMetric := -1
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	sc.Scan() // skip header
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 7 {
			continue
		}
		iface := f[0]
		dest := f[1]
		if dest != "00000000" {
			continue
		}
		metric, _ := strconv.Atoi(f[6])
		if bestMetric == -1 || metric < bestMetric {
			best, bestMetric = iface, metric
		}
	}
	return best
}

// memInfo returns (available, total) bytes from /proc/meminfo.
func memInfo() (uint64, uint64) {
	data, err := os.ReadFile("/proc/meminfo")
	if err != nil {
		return 0, 0
	}
	var total, available uint64
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		f := strings.Fields(sc.Text())
		if len(f) < 2 {
			continue
		}
		val, _ := strconv.ParseUint(f[1], 10, 64)
		switch strings.TrimSuffix(f[0], ":") {
		case "MemTotal":
			total = val * 1024
		case "MemAvailable":
			available = val * 1024
		}
	}
	return available, total
}

func readUptime() float64 {
	data, err := os.ReadFile("/proc/uptime")
	if err != nil {
		return 0
	}
	f := strings.Fields(string(data))
	if len(f) == 0 {
		return 0
	}
	v, _ := strconv.ParseFloat(f[0], 64)
	return v
}

func readLoadAvg() []float64 {
	data, err := os.ReadFile("/proc/loadavg")
	if err != nil {
		return []float64{0, 0, 0}
	}
	f := strings.Fields(string(data))
	out := make([]float64, 3)
	for i := 0; i < 3 && i < len(f); i++ {
		v, _ := strconv.ParseFloat(f[i], 64)
		out[i] = v
	}
	return out
}

func readHostname() string {
	h, err := os.Hostname()
	if err != nil {
		return ""
	}
	return h
}

func readKernelRelease() string {
	data, err := os.ReadFile("/proc/sys/kernel/osrelease")
	if err != nil {
		return runtime.GOOS
	}
	return strings.TrimSpace(string(data))
}

func readCPUModel() string {
	data, err := os.ReadFile("/proc/cpuinfo")
	if err != nil {
		return "unknown"
	}
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "model name") {
			if i := strings.Index(line, ":"); i >= 0 {
				return strings.TrimSpace(line[i+1:])
			}
		}
	}
	return "unknown"
}
