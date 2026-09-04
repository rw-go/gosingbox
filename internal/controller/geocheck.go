package controller

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"sync"
	"time"
)

const (
	geocheckTimeoutMs = 45_000
	geocheckMaxOutput = 32 * 1024 * 1024
)

var (
	geocheckMu      sync.Mutex
	geocheckRunning bool
)

// cappedBuffer bounds total output and cancels the command's context as soon as
// the limit is exceeded, so a misbehaving helper cannot inflate memory.
type cappedBuffer struct {
	mu       sync.Mutex
	buf      bytes.Buffer
	max      int
	cancel   context.CancelFunc
	exceeded bool
}

func (c *cappedBuffer) Write(p []byte) (int, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.buf.Len()+len(p) > c.max {
		if !c.exceeded {
			c.exceeded = true
			if c.cancel != nil {
				c.cancel()
			}
		}
		return 0, fmt.Errorf("output exceeds %d bytes", c.max)
	}
	return c.buf.Write(p)
}

func (c *cappedBuffer) Bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.Bytes()
}

func geocheckBin() string {
	if v := os.Getenv("GEOCHECK_BIN_PATH"); v != "" {
		return v
	}
	return "/usr/local/bin/geocheck"
}

func resolveGeocheckBind(ip, iface string) (string, error) {
	if ip != "" {
		if net.ParseIP(ip) == nil {
			return "", fmt.Errorf(`Geocheck: %q is not a valid IP address.`, ip)
		}
		return ip, nil
	}
	if iface == "" {
		return "", nil
	}
	if _, err := net.InterfaceByName(iface); err != nil {
		return "", fmt.Errorf(`Geocheck: network interface %q is not available.`, iface)
	}
	return iface, nil
}

// geocheckRun invokes the external geocheck binary and returns its parsed
// JSON report (mirrors the Node.js GeocheckService). ip and iface are optional
// bind targets.
func geocheckRun(ip, iface string) (map[string]any, error) {
	bindTo, err := resolveGeocheckBind(ip, iface)
	if err != nil {
		return nil, err
	}

	geocheckMu.Lock()
	if geocheckRunning {
		geocheckMu.Unlock()
		return nil, fmt.Errorf("Geocheck: a run is already in progress.")
	}
	geocheckRunning = true
	geocheckMu.Unlock()
	defer func() {
		geocheckMu.Lock()
		geocheckRunning = false
		geocheckMu.Unlock()
	}()

	args := []string{}
	if bindTo != "" {
		args = append(args, "--interface", bindTo)
	}
	args = append(args, "--json", "--svg-base64", "--quiet")

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(geocheckTimeoutMs)*time.Millisecond)
	defer cancel()

	var out cappedBuffer
	out.max = geocheckMaxOutput
	out.cancel = cancel

	cmd := exec.CommandContext(ctx, geocheckBin(), args...)
	cmd.Stdout = &out
	cmd.Stderr = &out

	err = cmd.Run()
	if out.exceeded {
		return nil, fmt.Errorf("Geocheck output too large")
	}
	if ctx.Err() != nil {
		return nil, fmt.Errorf("Geocheck via %s exceeded %dms and was killed.", orDefaultRoute(bindTo), geocheckTimeoutMs)
	}
	if err != nil {
		return nil, fmt.Errorf("Geocheck via %s failed: %v", orDefaultRoute(bindTo), err)
	}

	var report map[string]any
	if err := json.Unmarshal(out.Bytes(), &report); err != nil {
		return nil, fmt.Errorf("Geocheck output is not valid JSON: %v", err)
	}
	img, _ := report["image"].(map[string]any)
	if img == nil || img["data"] == "" {
		return nil, fmt.Errorf("geocheck report carries no image")
	}
	return report, nil
}

func orDefaultRoute(bind string) string {
	if bind == "" {
		return "default route"
	}
	return bind
}
