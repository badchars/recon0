package provider

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
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
	hardTimeoutMin := config.GetInt(extra, "hard_timeout", 15)
	ctx, cancel := context.WithTimeout(ctx, time.Duration(hardTimeoutMin)*time.Minute)
	defer cancel()
	responsesDir := filepath.Join(opts.WorkDir, "responses")

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
		// Metadata extraction
		"-sc", "-title", "-td", "-server", "-ct", "-cl", "-rt", "-ip", "-cname",
		"-location",
		"-cdn",
		"-method",
		"-websocket",
		"-hash", "sha256",
		"-favicon",
		"-tls-grab", "-tls-probe",
		"-http2",
		"-vhost",
		"-extract-fqdn",
		"-include-chain",
		// Follow redirects
		"-fr",
		// Store response bodies
		"-sr", "-srd", responsesDir,
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

	if err := cmd.Run(); err != nil {
		// httpx may return non-zero even with partial results
		count := 0
		if urls, _ := extractJSONField(jsonOut, "url"); len(urls) > 0 {
			writeLines(opts.Output, urls)
			count = len(urls)
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
