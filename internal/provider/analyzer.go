package provider

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/badchars/recon0/internal/config"
	"github.com/badchars/recon0/internal/dsl"
)

type Analyzer struct{}

func (a *Analyzer) Name() string       { return "analyzer" }
func (a *Analyzer) Stage() string      { return "analyze" }
func (a *Analyzer) OutputType() string { return "findings" }
func (a *Analyzer) Check() error       { return nil }

func (a *Analyzer) Run(ctx context.Context, opts *RunOpts) (*Result, error) {
	extra := opts.Config
	harDir := filepath.Join(opts.WorkDir, "har")
	jsDir := filepath.Join(opts.WorkDir, "js")

	// Load rules
	rules, err := dsl.LoadDefaultRules()
	if err != nil {
		return nil, fmt.Errorf("analyzer: load default rules: %w", err)
	}

	// Load custom rules if configured
	customPath := config.GetString(extra, "custom_rules", "")
	if customPath != "" {
		custom, err := dsl.LoadCustomRules(customPath)
		if err != nil {
			// Non-fatal: log and continue with defaults
			fmt.Fprintf(os.Stderr, "analyzer: custom rules error: %v\n", err)
		} else {
			rules = dsl.MergeRules(rules, custom)
		}
	}

	// Compile rules
	if err := dsl.CompileRules(rules); err != nil {
		return nil, fmt.Errorf("analyzer: compile rules: %w", err)
	}

	engine := dsl.NewEngine(rules)

	// Load JS manifest for URL enrichment
	jsManifest := loadJSManifest(filepath.Join(jsDir, "_manifest.json"))
	engine.SetJSManifest(jsManifest)

	// Scan HAR files (full content + headers)
	harFiles, _ := filepath.Glob(filepath.Join(harDir, "*.har"))
	for _, harFile := range harFiles {
		if ctx.Err() != nil {
			break
		}
		engine.ScanHAR(harFile)
		engine.ScanHARHeaders(harFile)
	}

	// Scan JS files (skip manifest)
	jsFiles, _ := filepath.Glob(filepath.Join(jsDir, "*"))
	for _, jsFile := range jsFiles {
		if ctx.Err() != nil {
			break
		}
		if filepath.Base(jsFile) == "_manifest.json" {
			continue
		}
		engine.ScanJSFile(jsFile)
	}

	// Scan endpoints if available
	endpointsFile := filepath.Join(opts.WorkDir, "output", "endpoints.json")
	if _, err := os.Stat(endpointsFile); err == nil {
		engine.ScanEndpoints(endpointsFile)
	}

	// Get deduplicated findings
	findings := engine.DeduplicatedFindings()

	// Write output (JSON Lines)
	os.MkdirAll(filepath.Dir(opts.Output), 0755)
	outFile, err := os.Create(opts.Output)
	if err != nil {
		return nil, fmt.Errorf("analyzer: create output: %w", err)
	}
	defer outFile.Close()

	writer := bufio.NewWriter(outFile)
	for _, f := range findings {
		data, _ := json.Marshal(f)
		fmt.Fprintln(writer, string(data))
	}
	writer.Flush()

	// Count by severity
	severityCounts := map[string]int{}
	for _, f := range findings {
		severityCounts[string(f.Severity)]++
	}

	return &Result{
		Count:      len(findings),
		OutputFile: opts.Output,
		Extra: map[string]any{
			"har_files_scanned": len(harFiles),
			"js_files_scanned":  len(jsFiles),
			"rules_loaded":      len(rules),
			"severity_counts":   severityCounts,
		},
	}, nil
}

func init() { Register(&Analyzer{}) }
