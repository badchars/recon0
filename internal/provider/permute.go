package provider

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"

	"github.com/badchars/recon0/internal/config"
)

// Permute expands the alive subdomain list via permutation generation
// (alterx) and then resolves the candidates with dnsx. It is intended
// to run after the resolve stage and produces additional alive hosts
// that get merged back into output/alive.txt.
type Permute struct{}

func (p *Permute) Name() string       { return "permute" }
func (p *Permute) Stage() string      { return "permute" }
func (p *Permute) OutputType() string { return "resolved" }

func (p *Permute) Check() error {
	if err := CheckBinary("alterx"); err != nil {
		return err
	}
	if err := CheckBinary("dnsx"); err != nil {
		return err
	}
	return nil
}

func (p *Permute) Run(ctx context.Context, opts *RunOpts) (*Result, error) {
	extra := opts.Config
	maxCandidates := config.GetInt(extra, "max_candidates", 50000)
	enrich := config.GetBool(extra, "enrich", true)

	// Phase 1 — alterx: derive permutation candidates from the alive list.
	permsFile := filepath.Join(opts.WorkDir, "raw", "alterx.permutations.txt")
	opts.ProgressFile = permsFile

	alterxArgs := []string{
		"-l", opts.Input,
		"-o", permsFile,
		"-silent",
	}
	// Pass -limit directly to alterx so it stops generating early instead of
	// blowing up cartesian-style across patterns × words × numbers.
	if maxCandidates > 0 {
		alterxArgs = append(alterxArgs, "-limit", strconv.Itoa(maxCandidates))
	}
	if enrich {
		alterxArgs = append(alterxArgs, "-enrich")
	}
	for _, pat := range extractPatterns(extra) {
		alterxArgs = append(alterxArgs, "-p", pat)
	}

	alterxCmd := exec.CommandContext(ctx, "alterx", alterxArgs...)
	if errFile, err := OpenLogFile(opts.LogDir, "alterx"); err == nil {
		defer errFile.Close()
		alterxCmd.Stderr = errFile
	}
	if err := alterxCmd.Run(); err != nil {
		return &Result{OutputFile: opts.Output}, fmt.Errorf("alterx: %w", err)
	}

	// Defensive post-cap (in case alterx ignores -limit for some pattern combo).
	if maxCandidates > 0 {
		if err := capLines(permsFile, maxCandidates); err != nil {
			return &Result{OutputFile: opts.Output}, fmt.Errorf("cap candidates: %w", err)
		}
	}
	candidateCount := LineCount(permsFile)
	if candidateCount == 0 {
		// Nothing generated — write empty output and exit cleanly.
		_ = os.WriteFile(opts.Output, nil, 0644)
		return &Result{
			Count:      0,
			OutputFile: opts.Output,
			Extra: map[string]any{
				"candidates": 0,
				"new_alive":  0,
			},
		}, nil
	}

	// Phase 2 — dnsx: resolve candidates, filtering wildcard IPs detected
	// during the resolve stage. The wildcard list is optional; if absent
	// (resolve found no wildcards) we proceed without -wd flags.
	opts.ProgressFile = opts.Output

	jsonOut := opts.Output + ".json"
	dnsxArgs := []string{
		"-l", permsFile,
		"-a", "-cname",
		"-re",
		"-t", strconv.Itoa(opts.Res.ThreadsDNS),
		"-retry", "2",
		"-json", "-o", jsonOut,
	}

	wcFile := filepath.Join(opts.WorkDir, "raw", "wildcard-domains.txt")
	if wcDomains := readLinesIfExists(wcFile); len(wcDomains) > 0 {
		for _, wd := range wcDomains {
			dnsxArgs = append(dnsxArgs, "-wd", wd)
		}
	}

	dnsxCmd := exec.CommandContext(ctx, "dnsx", dnsxArgs...)
	if errFile, err := OpenLogFile(opts.LogDir, "permute-dnsx"); err == nil {
		defer errFile.Close()
		dnsxCmd.Stderr = errFile
	}
	if err := dnsxCmd.Run(); err != nil {
		return &Result{OutputFile: opts.Output}, fmt.Errorf("permute dnsx: %w", err)
	}

	alive, err := extractJSONField(jsonOut, "host")
	if err != nil {
		return &Result{OutputFile: opts.Output}, fmt.Errorf("permute parse: %w", err)
	}
	writeLines(opts.Output, alive)

	return &Result{
		Count:      len(alive),
		OutputFile: opts.Output,
		Extra: map[string]any{
			"candidates": candidateCount,
			"new_alive":  len(alive),
		},
	}, nil
}

func init() { Register(&Permute{}) }

// ── helpers ──

// extractPatterns pulls user-provided alterx patterns out of the YAML
// config. YAML lists decode into []any whose elements are strings.
func extractPatterns(extra map[string]any) []string {
	raw, ok := extra["patterns"].([]any)
	if !ok {
		return nil
	}
	var pats []string
	for _, p := range raw {
		if s, ok := p.(string); ok && s != "" {
			pats = append(pats, s)
		}
	}
	return pats
}

// capLines truncates a file in-place to at most maxN lines. Used as a
// safety net when alterx generates an excessive number of candidates.
func capLines(path string, maxN int) error {
	if LineCount(path) <= maxN {
		return nil
	}

	src, err := os.Open(path)
	if err != nil {
		return err
	}
	defer src.Close()

	tmpPath := path + ".tmp"
	dst, err := os.Create(tmpPath)
	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(src)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	w := bufio.NewWriter(dst)
	written := 0
	for scanner.Scan() && written < maxN {
		fmt.Fprintln(w, scanner.Text())
		written++
	}
	w.Flush()
	dst.Close()

	return os.Rename(tmpPath, path)
}

// readLinesIfExists returns the lines of a file if it exists; otherwise nil.
// Used for optional cross-stage data (e.g. wildcard list from resolve).
func readLinesIfExists(path string) []string {
	if _, err := os.Stat(path); err != nil {
		return nil
	}
	return readLines(path)
}
