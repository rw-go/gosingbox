// Package singbox manages the sing-box data plane subprocess.
package singbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"time"
)

// Process manages the sing-box child process lifecycle.
type Process struct {
	logger    *slog.Logger
	binPath   string
	confPath  string
	statsAddr string
	logDir    string
	logLevel  string
	drainMs   time.Duration

	mu            sync.Mutex
	cmd           *exec.Cmd
	expectedExit  bool
	stopping      bool
	supervisorRun bool
	relaunchCount int
	restartCount  int
	currentUsers  []string
	version       string
	online        bool
}

type Status struct {
	Up      bool
	Pid     int
	Version string
}

// Options configures the process manager.
type Options struct {
	BinPath   string
	ConfPath  string
	StatsAddr string
	LogDir    string
	LogLevel  string
	DrainMs   time.Duration
	Logger    *slog.Logger
}

// NewProcess creates a sing-box process manager.
func NewProcess(opts Options) *Process {
	if opts.BinPath == "" {
		opts.BinPath = "/usr/local/bin/sing-box"
	}
	if opts.ConfPath == "" {
		opts.ConfPath = "/var/lib/rnode/singbox/config.json"
	}
	if opts.StatsAddr == "" {
		opts.StatsAddr = "127.0.0.1:6450"
	}
	if opts.LogDir == "" {
		opts.LogDir = "/var/log/rnode"
	}
	if opts.LogLevel == "" {
		opts.LogLevel = "warn"
	}
	if opts.DrainMs == 0 {
		opts.DrainMs = 3 * time.Second
	}
	if opts.Logger == nil {
		opts.Logger = slog.New(slog.NewTextHandler(os.Stderr, nil))
	}
	return &Process{
		logger:    opts.Logger,
		binPath:   opts.BinPath,
		confPath:  opts.ConfPath,
		statsAddr: opts.StatsAddr,
		logDir:    opts.LogDir,
		logLevel:  opts.LogLevel,
		drainMs:   opts.DrainMs,
	}
}

func (p *Process) BinPath() string   { return p.binPath }
func (p *Process) ConfPath() string  { return p.confPath }
func (p *Process) StatsAddr() string { return p.statsAddr }
func (p *Process) LogLevel() string  { return p.logLevel }

// IsRunning reports whether the child process is alive.
func (p *Process) IsRunning() bool {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.cmd != nil && p.cmd.Process != nil && p.cmd.ProcessState == nil
}

// Pid returns the child pid, or 0 if not running.
func (p *Process) Pid() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.cmd != nil && p.cmd.Process != nil && p.cmd.ProcessState == nil {
		return p.cmd.Process.Pid
	}
	return 0
}

// Version returns the detected sing-box version.
func (p *Process) Version() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.version
}

func (p *Process) RestartCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.restartCount
}

func (p *Process) CurrentUsers() []string {
	p.mu.Lock()
	defer p.mu.Unlock()
	out := make([]string, len(p.currentUsers))
	copy(out, p.currentUsers)
	return out
}

// Status returns a snapshot.
func (p *Process) Status() Status {
	return Status{Up: p.IsRunning(), Pid: p.Pid(), Version: p.Version()}
}

// spawn starts the sing-box child with the current config file.
func (p *Process) spawn() {
	if p.IsRunning() {
		p.logger.Warn("sing-box already running; skipping spawn")
		return
	}
	for _, dir := range []string{filepath.Dir(p.confPath), p.logDir} {
		_ = os.MkdirAll(dir, 0o755)
	}

	p.expectedExit = false
	p.logger.Info("spawning sing-box", "bin", p.binPath, "config", p.confPath)

	logPath := filepath.Join(p.logDir, fmt.Sprintf("singbox-%d.log", time.Now().Unix()))
	logFile, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		p.logger.Warn("cannot open singbox log", "path", logPath, "error", err)
	}

	cmd := exec.Command(p.binPath, "run", "-c", p.confPath)
	cmd.Stdout = logFile
	cmd.Stderr = logFile

	if err := cmd.Start(); err != nil {
		p.logger.Error("sing-box failed to start", "error", err)
		if logFile != nil {
			_ = logFile.Close()
		}
		p.scheduleRelaunch()
		return
	}

	p.mu.Lock()
	p.cmd = cmd
	p.relaunchCount = 0
	p.mu.Unlock()

	// Register the wait channel now so stop() can rendezvous with the exit
	// goroutine without a second Wait call.
	_ = p.markWait(cmd)

	go func() {
		_ = cmd.Wait()
		if logFile != nil {
			_ = logFile.Close()
		}
		p.finishWait(cmd)
		p.mu.Lock()
		if p.cmd == cmd {
			p.cmd = nil
		}
		expected := p.expectedExit || p.stopping
		p.mu.Unlock()

		p.logger.Warn("sing-box exited", "pid", cmd.Process.Pid, "expected", expected)
		if expected {
			return
		}
		p.scheduleRelaunch()
	}()

	go func() { _ = p.refreshVersion() }()
}

// stop gracefully stops the child (SIGTERM then SIGKILL after drain).
func (p *Process) stop() {
	p.mu.Lock()
	cmd := p.cmd
	if cmd == nil || cmd.Process == nil || cmd.ProcessState != nil {
		p.cmd = nil
		p.mu.Unlock()
		return
	}
	p.expectedExit = true
	p.mu.Unlock()

	done := p.markWait(cmd)
	_ = cmd.Process.Signal(syscall.SIGTERM)

	select {
	case <-done:
	case <-time.After(10 * time.Second):
		p.logger.Warn("sing-box did not exit in time; forcing SIGKILL")
		_ = cmd.Process.Kill()
		<-done
	}

	p.mu.Lock()
	if p.cmd == cmd {
		p.cmd = nil
	}
	p.mu.Unlock()
}

// waiters tracks a completion channel per cmd so stop() and the exit goroutine
// do not both call Wait on the same process.
type waiter struct{ done chan struct{} }

var waiters sync.Map // *exec.Cmd -> chan struct{}

func (p *Process) markWait(cmd *exec.Cmd) chan struct{} {
	if v, ok := waiters.Load(cmd); ok {
		return v.(chan struct{})
	}
	ch := make(chan struct{})
	waiters.Store(cmd, ch)
	return ch
}

func (p *Process) finishWait(cmd *exec.Cmd) {
	if v, ok := waiters.Load(cmd); ok {
		if ch, ok := v.(chan struct{}); ok {
			select {
			case <-ch:
			default:
				close(ch)
			}
		}
		waiters.Delete(cmd)
	}
}

// ApplyConfig writes the candidate config, checks it, then gracefully
// restarts. On check failure the old config/process is kept.
func (p *Process) ApplyConfig(config map[string]any) error {
	candidate := p.confPath + ".candidate"
	if err := os.MkdirAll(filepath.Dir(p.confPath), 0o755); err != nil {
		return err
	}

	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	// Ensure the geo/cache directory (used by remote rule-sets) exists before
	// sing-box runs, otherwise it fails with "no such file or directory".
	if cachePath, ok := config["experimental"].(map[string]any)["cache_file"].(map[string]any)["path"].(string); ok && cachePath != "" {
		if dir := filepath.Dir(cachePath); dir != "" {
			_ = os.MkdirAll(dir, 0o755)
		}
	}
	if err := os.WriteFile(candidate, data, 0o644); err != nil {
		return err
	}

	if err := p.checkFile(candidate); err != nil {
		// Keep old config; retain the failed candidate for diagnosis.
		_ = os.Rename(candidate, candidate+".failed")
		p.logger.Error("sing-box check failed; keeping old config",
			"error", err, "candidate", candidate+".failed")
		return err
	}

	p.mu.Lock()
	p.currentUsers = extractUsers(config)
	p.restartCount++
	p.mu.Unlock()

	p.stop()
	if err := os.Rename(candidate, p.confPath); err != nil {
		_ = os.Remove(candidate)
		p.spawn()
		return err
	}
	p.spawn()

	// Wait until the v2ray_api endpoint responds.
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if p.waitUntilOnline(ctx) {
		p.logger.Info("sing-box restarted with new configuration")
	} else {
		p.logger.Error("sing-box failed to come online after restart")
		return errors.New("sing-box failed to come online after restart")
	}
	return nil
}

// checkFile runs `sing-box check -c <path>`.
func (p *Process) checkFile(path string) error {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, p.binPath, "check", "-c", path)
	out, err := cmd.CombinedOutput()
	if err != nil {
		msg := strings.TrimSpace(string(out))
		if msg == "" {
			msg = err.Error()
		}
		return fmt.Errorf("sing-box check failed: %s", msg)
	}
	return nil
}

func (p *Process) waitUntilOnline(ctx context.Context) bool {
	ticker := time.NewTicker(250 * time.Millisecond)
	defer ticker.Stop()
	for {
		if !p.IsRunning() {
			return false
		}
		if p.ping(ctx) {
			return true
		}
		select {
		case <-ctx.Done():
			return false
		case <-ticker.C:
		}
	}
}

func (p *Process) refreshVersion() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, p.binPath, "version")
	out, err := cmd.Output()
	if err != nil {
		return err
	}
	first := strings.TrimSpace(strings.SplitN(string(out), "\n", 2)[0])
	var v string
	if i := strings.Index(first, " "); i >= 0 {
		v = strings.TrimSpace(first[i+1:])
	} else {
		v = first
	}
	p.mu.Lock()
	p.version = v
	p.mu.Unlock()
	return nil
}

func (p *Process) scheduleRelaunch() {
	p.mu.Lock()
	if p.supervisorRun {
		p.mu.Unlock()
		return
	}
	p.supervisorRun = true
	p.mu.Unlock()

	go func() {
		defer func() {
			p.mu.Lock()
			p.supervisorRun = false
			p.mu.Unlock()
		}()
		for {
			p.mu.Lock()
			stopping := p.stopping || p.expectedExit
			running := p.cmd != nil && p.cmd.Process != nil && p.cmd.ProcessState == nil
			attempt := p.relaunchCount
			p.mu.Unlock()
			if stopping || running {
				return
			}
			delay := time.Duration(500*(1<<uint(attempt))) * time.Millisecond
			if delay > 30*time.Second {
				delay = 30 * time.Second
			}
			p.mu.Lock()
			p.relaunchCount++
			p.mu.Unlock()

			time.Sleep(delay)

			p.mu.Lock()
			if p.stopping || p.expectedExit {
				p.mu.Unlock()
				return
			}
			p.mu.Unlock()
			if !p.IsRunning() {
				p.logger.Warn("sing-box crashed; relaunching", "attempt", attempt+1, "delay", delay.String())
				p.spawn()
			}
		}
	}()
}

// Shutdown stops the process (for application shutdown).
func (p *Process) Shutdown() {
	p.mu.Lock()
	p.stopping = true
	p.expectedExit = true
	p.mu.Unlock()
	p.stop()
}

func extractUsers(config map[string]any) []string {
	var out []string
	inbounds, _ := config["inbounds"].([]any)
	for _, ibAny := range inbounds {
		ib, _ := ibAny.(map[string]any)
		users, _ := ib["users"].([]any)
		for _, uAny := range users {
			u, _ := uAny.(map[string]any)
			if id, ok := u["uuid"].(string); ok && id != "" {
				out = append(out, id)
			}
		}
	}
	return out
}
