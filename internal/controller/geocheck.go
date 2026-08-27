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

func geocheckBin() string {
	if v := os.Getenv("GEOCHECK_BIN_PATH"); v != "" {
		return v
	}
	return "/usr/local/bin/geocheck"
}

// geocheckRun invokes the external geocheck binary and returns its parsed
// JSON report (mirrors the Node.js GeocheckService). ip and iface are optional
// bind targets.
func geocheckRun(ip, iface string) (map[string]any, error) {
	bindTo := ""
	if ip != "" {
		if net.ParseIP(ip) == nil {
			return nil, fmt.Errorf(`Geocheck: %q is not a valid IP address.`, ip)
		}
		bindTo = ip
	} else if iface != "" {
		bindTo = iface
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

	cmd := exec.CommandContext(ctx, geocheckBin(), args...)
	var out bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &out

	err := cmd.Run()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("Geocheck via %s exceeded %dms and was killed.", orDefaultRoute(bindTo), geocheckTimeoutMs)
	}
	if err != nil {
		return nil, fmt.Errorf("Geocheck via %s failed: %v", orDefaultRoute(bindTo), err)
	}
	if out.Len() > geocheckMaxOutput {
		return nil, fmt.Errorf("Geocheck output too large")
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