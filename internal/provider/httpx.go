package provider

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/badchars/recon0/internal/config"
)

type Httpx struct{}

func (h *Httpx) Name() string       { return "httpx" }
func (h *Httpx) Stage() string      { return "probe" }
func (h *Httpx) OutputType() string { return "hosts" }
func (h *Httpx) Check() error       { return CheckBinary("httpx") }

func (h *Httpx) Run(ctx context.Context, opts *RunOpts) (*Result, error) {
	jsonOut := opts.Output + ".json"
	opts.ProgressFile = jsonOut // monitor JSON output for live progress
	extra := opts.Config

	// Hard timeout: kill httpx after N minutes regardless of progress.
	// Partial results are preserved — the error path already handles this.
	hardTimeoutMin := config.GetInt(extra, "hard_timeout", 600)
	ctx, cancel := context.WithTimeout(ctx, time.Duration(hardTimeoutMin)*time.Minute)
	defer cancel()

	// Idle timeout: httpx writes a JSON line for every live service as it
	// probes. Some hosts (notably WAFs that never close the connection) leave
	// a worker hung after all real probing is done, so httpx sits idle for
	// hours until the hard timeout. If the output stops growing for this many
	// minutes we assume probing is effectively finished and kill httpx, keeping
	// the partial results. Generous default so genuinely slow/large scans (long
	// silent runs of dead ports) are never truncated. 0 disables.
	idleTimeoutMin := config.GetInt(extra, "idle_timeout", 5)

	// Build port list
	defaultPorts := []int{80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9090}
	ports := config.GetIntSlice(extra, "ports", defaultPorts)
	portStrs := make([]string, len(ports))
	for i, p := range ports {
		portStrs[i] = strconv.Itoa(p)
	}

	args := []string{
		"-l", opts.Input,
		"-ports", strings.Join(portStrs, ","),
		// Metadata extraction (only fields consumed downstream by
		// collector intel, smartfuzz tech-aware probing, and the web panel)
		"-sc", "-title", "-td", "-server", "-ct", "-cl", "-ip", "-cname",
		"-location",
		"-cdn",
		"-tls-grab", "-tls-probe",
		"-http2",
		// Follow redirects
		"-fr",
		// Performance
		"-t", strconv.Itoa(opts.Res.ThreadsLight),
		"-rl", strconv.Itoa(opts.Res.RateFull),
		"-timeout", "5",
		"-retries", "1",
		"-no-fallback",
		// Output
		"-json", "-o", jsonOut,
	}

	cmd := exec.CommandContext(ctx, "httpx", args...)
	errFile, err := OpenLogFile(opts.LogDir, "httpx")
	if err == nil {
		defer errFile.Close()
		cmd.Stderr = errFile
	}

	if err := cmd.Start(); err != nil {
		return &Result{OutputFile: opts.Output}, fmt.Errorf("httpx: %w", err)
	}

	// Idle watchdog (see idleTimeoutMin above). Polls the JSON output line
	// count; if it hasn't grown for idleTimeoutMin, httpx is hung on a stuck
	// connection — kill it and let the partial-results path below run.
	var idleKilled atomic.Bool
	watchDone := make(chan struct{})
	if idleTimeoutMin > 0 {
		go func() {
			ticker := time.NewTicker(15 * time.Second)
			defer ticker.Stop()
			idleLimit := time.Duration(idleTimeoutMin) * time.Minute
			lastCount := 0
			lastChange := time.Now()
			for {
				select {
				case <-watchDone:
					return
				case <-ctx.Done():
					return
				case <-ticker.C:
					c := LineCount(jsonOut)
					if c != lastCount {
						lastCount = c
						lastChange = time.Now()
						continue
					}
					// Only act once we've seen output and it then stalls; a run
					// that has produced nothing yet may still be working through
					// dead ports, so leave that case to the hard timeout.
					if c > 0 && time.Since(lastChange) >= idleLimit {
						idleKilled.Store(true)
						if errFile != nil {
							fmt.Fprintf(errFile, "\n[recon0] idle timeout: no new output for %dm — killing httpx, keeping %d partial results\n", idleTimeoutMin, c)
						}
						_ = cmd.Process.Kill()
						return
					}
				}
			}
		}()
	}

	err = cmd.Wait()
	close(watchDone)

	if err != nil {
		// httpx may return non-zero even with partial results
		count := 0
		if urls, _ := extractJSONField(jsonOut, "url"); len(urls) > 0 {
			writeLines(opts.Output, urls)
			count = len(urls)
		}
		// An idle kill is expected, not a failure: httpx had finished probing
		// and was only hung on a stuck connection. Report success.
		if idleKilled.Load() {
			return &Result{Count: count, OutputFile: opts.Output}, nil
		}
		return &Result{Count: count, OutputFile: opts.Output}, fmt.Errorf("httpx: %w", err)
	}

	// Extract plain URLs from JSON
	urls, _ := extractJSONField(jsonOut, "url")
	writeLines(opts.Output, urls)

	return &Result{
		Count:      len(urls),
		OutputFile: opts.Output,
	}, nil
}

func init() { Register(&Httpx{}) }
