package provider

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/badchars/recon0/internal/config"
	"github.com/badchars/recon0/internal/llm"
)

type Collector struct{}

func (c *Collector) Name() string       { return "collector" }
func (c *Collector) Stage() string      { return "collect" }
func (c *Collector) OutputType() string { return "intel" }
func (c *Collector) Check() error       { return nil }

func (c *Collector) Run(ctx context.Context, opts *RunOpts) (*Result, error) {
	extra := opts.Config
	outputDir := filepath.Join(opts.WorkDir, "output")
	rawDir := filepath.Join(opts.WorkDir, "raw")

	// Read target domain
	target := ReadDomainFromFile(filepath.Join(opts.WorkDir, "input", "domains.txt"))

	// Build intelligence report
	report := &llm.IntelligenceReport{
		Target:      target,
		GeneratedAt: time.Now().UTC().Format(time.RFC3339),
	}

	// Counts
	report.SubdomainCount = LineCount(filepath.Join(outputDir, "subdomains.txt"))
	report.LiveHostCount = LineCount(filepath.Join(outputDir, "live-hosts.txt"))
	report.OpenPortCount = LineCount(filepath.Join(outputDir, "ports.txt"))
	report.EndpointCount = LineCount(filepath.Join(outputDir, "endpoints.json"))

	// Build host inventory from httpx + tlsx + naabu
	report.Hosts = buildHostInventory(rawDir)

	// Load findings
	findingsPath := filepath.Join(outputDir, "findings.json")
	report.Findings = loadFindings(findingsPath)

	// Build attack surface (scoped to target domain)
	report.AttackSurface = buildAttackSurface(
		filepath.Join(outputDir, "endpoints.json"),
		report.Findings,
		target,
	)

	// LLM enrichment (optional)
	llmEnabled := config.GetBool(extra, "llm_enabled", false)
	if llmEnabled {
		llmProvider := config.GetString(extra, "llm_provider", "openai")
		llmModel := config.GetString(extra, "llm_model", "gpt-4o")
		llmAPIKey := config.GetString(extra, "llm_api_key", "")
		llmBaseURL := config.GetString(extra, "llm_base_url", "")
		llmMaxTokens := config.GetInt(extra, "llm_max_tokens", 4096)

		if llmAPIKey != "" {
			client := llm.NewClient(llmProvider, llmModel, llmAPIKey, llmBaseURL, llmMaxTokens)
			messages := llm.BuildAnalysisPrompt(report)

			llmCtx, llmCancel := context.WithTimeout(ctx, 60*time.Second)
			defer llmCancel()

			response, err := client.Complete(llmCtx, messages)
			if err != nil {
				fmt.Fprintf(os.Stderr, "collector: LLM analysis failed (non-fatal): %v\n", err)
			} else {
				llm.ParseLLMResponse(response, report)
			}
		}
	}

	// Write intel.json
	os.MkdirAll(filepath.Dir(opts.Output), 0755)
	reportJSON, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("collector: marshal report: %w", err)
	}
	if err := os.WriteFile(opts.Output, reportJSON, 0644); err != nil {
		return nil, fmt.Errorf("collector: write output: %w", err)
	}

	// Also write attack-surface.json (subset)
	surfacePath := filepath.Join(outputDir, "attack-surface.json")
	surfaceJSON, _ := json.MarshalIndent(report.AttackSurface, "", "  ")
	os.WriteFile(surfacePath, surfaceJSON, 0644)

	return &Result{
		Count:      len(report.Findings),
		OutputFile: opts.Output,
		Extra: map[string]any{
			"subdomains":      report.SubdomainCount,
			"live_hosts":      report.LiveHostCount,
			"open_ports":      report.OpenPortCount,
			"endpoints":       report.EndpointCount,
			"findings":        len(report.Findings),
			"hosts_profiled":  len(report.Hosts),
			"llm_enabled":     llmEnabled,
			"intel_generated": 1,
		},
	}, nil
}

// ── Host Inventory Builder ──

// buildHostInventory merges httpx, tlsx, and naabu data into per-host profiles.
func buildHostInventory(rawDir string) []llm.HostInfo {
	hosts := make(map[string]*llm.HostInfo) // keyed by hostname

	getHost := func(name string) *llm.HostInfo {
		if h, ok := hosts[name]; ok {
			return h
		}
		h := &llm.HostInfo{Host: name}
		hosts[name] = h
		return h
	}

	// Parse httpx JSON (richest source: tech, status, CDN, CNAME, TLS, server)
	parseJSONLines(filepath.Join(rawDir, "httpx.hosts.txt.json"), func(line []byte) {
		var entry struct {
			Host       string   `json:"host"`
			URL        string   `json:"url"`
			IP         string   `json:"host_ip"`
			StatusCode int      `json:"status_code"`
			Tech       []string `json:"tech"`
			CDNName    string   `json:"cdn_name"`
			CNAME      []string `json:"cname"`
			FinalURL   string   `json:"final_url"`
			TLS        *struct {
				Version     string   `json:"tls_version"`
				IssuerCN    string   `json:"issuer_cn"`
				NotAfter    string   `json:"not_after"`
				Wildcard    bool     `json:"wildcard_certificate"`
				SubjectAN   []string `json:"subject_an"`
			} `json:"tls"`
		}
		if json.Unmarshal(line, &entry) != nil || entry.Host == "" {
			return
		}

		h := getHost(entry.Host)
		if h.URL == "" {
			h.URL = entry.URL
		}
		if h.IP == "" {
			h.IP = entry.IP
		}
		if entry.StatusCode > 0 {
			h.StatusCode = entry.StatusCode
		}
		if len(entry.Tech) > 0 {
			h.Tech = mergeStrings(h.Tech, entry.Tech)
		}
		if entry.CDNName != "" {
			h.CDN = entry.CDNName
		}
		if len(entry.CNAME) > 0 {
			h.CNAME = entry.CNAME
		}
		if entry.FinalURL != "" {
			h.FinalURL = entry.FinalURL
		}
		if entry.TLS != nil {
			h.TLSVersion = entry.TLS.Version
			h.TLSIssuer = entry.TLS.IssuerCN
			h.TLSExpiry = entry.TLS.NotAfter
			h.Wildcard = entry.TLS.Wildcard
		}
	})

	// Parse naabu JSON (open ports per host)
	parseJSONLines(filepath.Join(rawDir, "naabu.ports.txt.json"), func(line []byte) {
		var entry struct {
			Host string `json:"host"`
			Port int    `json:"port"`
			IP   string `json:"ip"`
		}
		if json.Unmarshal(line, &entry) != nil || entry.Host == "" {
			return
		}
		h := getHost(entry.Host)
		if h.IP == "" {
			h.IP = entry.IP
		}
		// Deduplicate ports
		found := false
		for _, p := range h.Ports {
			if p == entry.Port {
				found = true
				break
			}
		}
		if !found {
			h.Ports = append(h.Ports, entry.Port)
		}
	})

	// Convert map to sorted slice
	var result []llm.HostInfo
	for _, h := range hosts {
		result = append(result, *h)
	}
	return result
}

func mergeStrings(a, b []string) []string {
	seen := make(map[string]bool, len(a))
	for _, s := range a {
		seen[s] = true
	}
	result := append([]string{}, a...)
	for _, s := range b {
		if !seen[s] {
			result = append(result, s)
		}
	}
	return result
}

func parseJSONLines(path string, handler func([]byte)) {
	f, err := os.Open(path)
	if err != nil {
		return
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		handler(line)
	}
}

// ── Findings & Attack Surface (unchanged) ──

func loadFindings(path string) []llm.FindingSummary {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var findings []llm.FindingSummary
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		var finding llm.FindingSummary
		if err := json.Unmarshal([]byte(line), &finding); err != nil {
			continue
		}
		findings = append(findings, finding)
	}
	return findings
}

func buildAttackSurface(endpointsPath string, findings []llm.FindingSummary, targetDomain string) llm.AttackSurface {
	surface := llm.AttackSurface{}

	if f, err := os.Open(endpointsPath); err == nil {
		defer f.Close()
		scanner := bufio.NewScanner(f)
		scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
		for scanner.Scan() {
			var ep struct {
				URL     string `json:"url"`
				Context string `json:"context"`
			}
			if err := json.Unmarshal([]byte(scanner.Text()), &ep); err != nil {
				continue
			}

			if strings.HasPrefix(ep.URL, "http") && !isInScope(ep.URL, targetDomain) {
				continue
			}

			lower := strings.ToLower(ep.URL)
			switch {
			case strings.Contains(lower, "/api/") || strings.Contains(lower, "/v1/") ||
				strings.Contains(lower, "/v2/") || strings.Contains(lower, "/graphql"):
				surface.APIEndpoints = appendUnique(surface.APIEndpoints, ep.URL, 50)
			case strings.Contains(lower, "/admin") || strings.Contains(lower, "/wp-admin") ||
				strings.Contains(lower, "/cpanel"):
				surface.AdminPanels = appendUnique(surface.AdminPanels, ep.URL, 20)
			case strings.Contains(lower, ".env") || strings.Contains(lower, ".git") ||
				strings.Contains(lower, ".bak") || strings.Contains(lower, "config"):
				surface.ExposedFiles = appendUnique(surface.ExposedFiles, ep.URL, 20)
			}
		}
	}

	for _, f := range findings {
		if strings.Contains(f.RuleID, "port") || strings.Contains(f.Source, "port") {
			surface.InterestingPorts = appendUnique(surface.InterestingPorts, f.Value, 20)
		}
	}

	return surface
}

func appendUnique(slice []string, value string, maxLen int) []string {
	if len(slice) >= maxLen {
		return slice
	}
	for _, s := range slice {
		if s == value {
			return slice
		}
	}
	return append(slice, value)
}

func init() { Register(&Collector{}) }
