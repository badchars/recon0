package provider

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/badchars/recon0/internal/config"
)

// Provider is the interface every security tool must implement.
type Provider interface {
	Name() string
	Stage() string
	OutputType() string
	Check() error
	Run(ctx context.Context, opts *RunOpts) (*Result, error)
}

// RunOpts holds runtime parameters passed to a provider.
type RunOpts struct {
	Input        string
	Output       string
	ProgressFile string // file to monitor for progress (defaults to Output)
	WorkDir      string
	LogDir       string
	Config       map[string]any
	Res          *config.Resources
}

// Result holds the outcome of a provider run.
type Result struct {
	Count      int
	Duration   time.Duration
	OutputFile string
	Extra      map[string]any
}

// StateUpdater is the interface for updating pipeline state (avoids import cycle).
type StateUpdater interface {
	UpdateProvider(stage, name, status string, count int, durationS int, outputFile string)
	UpdateProgress(stagesDone, stagesTotal int, provider string, lines, elapsedS int)
	ClearProgress()
	AddError(stage, provider, errMsg string, fatal bool)
}

// Logger is the interface for provider logging (avoids import cycle).
type Logger interface {
	Provider(name, msg string, fields ...map[string]any)
}

// ── Registry ──

var (
	mu       sync.RWMutex
	registry = map[string]Provider{}
)

// Register adds a provider to the registry. Called from init().
func Register(p Provider) {
	mu.Lock()
	defer mu.Unlock()
	registry[p.Name()] = p
}

// Get returns a provider by name.
func Get(name string) (Provider, bool) {
	mu.RLock()
	defer mu.RUnlock()
	p, ok := registry[name]
	return p, ok
}

// All returns all registered providers.
func All() []Provider {
	mu.RLock()
	defer mu.RUnlock()
	list := make([]Provider, 0, len(registry))
	for _, p := range registry {
		list = append(list, p)
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name() < list[j].Name() })
	return list
}

// ByStage returns providers belonging to a given stage.
func ByStage(stage string) []Provider {
	mu.RLock()
	defer mu.RUnlock()
	var list []Provider
	for _, p := range registry {
		if p.Stage() == stage {
			list = append(list, p)
		}
	}
	sort.Slice(list, func(i, j int) bool { return list[i].Name() < list[j].Name() })
	return list
}

// Names returns sorted names of all registered providers.
func Names() []string {
	mu.RLock()
	defer mu.RUnlock()
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	sort.Strings(names)
	return names
}

// ── Runner Wrapper ──

// ProgressContext holds stage progress info for the progress monitor.
type ProgressContext struct {
	StagesDone  int
	StagesTotal int
}

// RunProvider executes a provider with timing, logging, state updates, and error capture.
func RunProvider(ctx context.Context, p Provider, opts *RunOpts, state StateUpdater, logger Logger, progCtx *ProgressContext) *Result {
	stageName := p.Stage()
	provName := p.Name()

	// Check binary
	if err := p.Check(); err != nil {
		logger.Provider(provName, fmt.Sprintf("binary not found, skipping (%v)", err))
		state.UpdateProvider(stageName, provName, "skipped", 0, 0, "")
		return &Result{Count: 0}
	}

	logger.Provider(provName, "starting", map[string]any{
		"stage": stageName,
		"input": opts.Input,
	})
	state.UpdateProvider(stageName, provName, "running", 0, 0, "")

	// Start live progress monitor (reads opts.ProgressFile dynamically — providers may set it during Run)
	stopProgress := startProgressMonitor(ctx, opts, provName, stageName, logger, state, progCtx)

	start := time.Now()
	result, err := p.Run(ctx, opts)
	elapsed := time.Since(start)
	durationS := int(elapsed.Seconds())

	// Stop progress monitor
	stopProgress()
	state.ClearProgress()

	if result == nil {
		result = &Result{}
	}
	result.Duration = elapsed

	if err != nil {
		logger.Provider(provName, fmt.Sprintf("failed after %s: %v", formatDur(elapsed), err))
		state.UpdateProvider(stageName, provName, "error", result.Count, durationS, "")
		state.AddError(stageName, provName, err.Error(), false)
	} else {
		logger.Provider(provName, fmt.Sprintf("done — %d results in %s", result.Count, formatDur(elapsed)),
			map[string]any{
				"count":    result.Count,
				"duration": formatDur(elapsed),
				"output":   result.OutputFile,
			})
		state.UpdateProvider(stageName, provName, "done", result.Count, durationS, result.OutputFile)
	}

	return result
}

// startProgressMonitor watches the output file and logs progress every 5 seconds.
// It dynamically checks opts.ProgressFile each tick, so providers can set it during Run().
func startProgressMonitor(ctx context.Context, opts *RunOpts, provName, stageName string,
	logger Logger, state StateUpdater, progCtx *ProgressContext) func() {

	done := make(chan struct{})
	go func() {
		ticker := time.NewTicker(5 * time.Second)
		defer ticker.Stop()
		start := time.Now()
		lastCount := 0

		for {
			select {
			case <-done:
				return
			case <-ctx.Done():
				return
			case <-ticker.C:
				// Resolve progress file dynamically (providers may set ProgressFile during Run)
				file := opts.Output
				if opts.ProgressFile != "" {
					file = opts.ProgressFile
				}

				count := LineCount(file)
				elapsed := int(time.Since(start).Seconds())

				if count != lastCount {
					logger.Provider(provName, fmt.Sprintf("progress — %s lines (%s)",
						formatNumber(count), formatDur(time.Since(start))))
					lastCount = count
				}

				// Update state with live progress
				if progCtx != nil {
					state.UpdateProgress(progCtx.StagesDone, progCtx.StagesTotal,
						provName, count, elapsed)
				}
			}
		}
	}()

	return func() { close(done) }
}

// formatNumber adds comma separators to numbers (1234567 → "1,234,567").
func formatNumber(n int) string {
	s := fmt.Sprintf("%d", n)
	if len(s) <= 3 {
		return s
	}
	var result []byte
	for i, c := range s {
		if i > 0 && (len(s)-i)%3 == 0 {
			result = append(result, ',')
		}
		result = append(result, byte(c))
	}
	return string(result)
}

// ── Helpers ──

// LineCount counts the number of lines in a file.
func LineCount(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()

	count := 0
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		count++
	}
	return count
}

// OpenLogFile opens (or creates) a .err log file for provider stderr.
func OpenLogFile(logDir, providerName string) (*os.File, error) {
	path := fmt.Sprintf("%s/%s.err", logDir, providerName)
	return os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
}

// ReadDomainFromFile reads the first line of a file (the target domain).
func ReadDomainFromFile(path string) string {
	f, err := os.Open(path)
	if err != nil {
		return ""
	}
	defer f.Close()
	scanner := bufio.NewScanner(f)
	if scanner.Scan() {
		return strings.TrimSpace(scanner.Text())
	}
	return ""
}

// CheckBinary verifies a tool binary exists in PATH.
func CheckBinary(name string) error {
	_, err := exec.LookPath(name)
	if err != nil {
		return fmt.Errorf("%s not found in PATH", name)
	}
	return nil
}

func formatDur(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	if d < time.Hour {
		m := int(d.Minutes())
		s := int(d.Seconds()) % 60
		return fmt.Sprintf("%dm%ds", m, s)
	}
	h := int(d.Hours())
	m := int(d.Minutes()) % 60
	return fmt.Sprintf("%dh%dm", h, m)
}
