package provider

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/badchars/recon0/internal/cdp"
	"github.com/badchars/recon0/internal/llm"
)

type Collector struct{}

func (c *Collector) Name() string       { return "collector" }
func (c *Collector) Stage() string      { return "collect" }
func (c *Collector) OutputType() string { return "intel" }
func (c *Collector) Check() error       { return nil }

// authInfo captures per-host authentication observed in HAR traffic.
type authInfo struct {
	HasAuth  bool
	AuthType string // Bearer, Cookie, Basic, API-Key
	Sample   string // truncated token sample for context
}

// ssrfParamNames are query parameter names that may indicate SSRF vectors.
var ssrfParamNames = map[string]bool{
	"url": true, "redirect": true, "callback": true, "next": true,
	"target": true, "dest": true, "return": true, "link": true,
	"file": true, "path": true, "src": true, "href": true,
	"uri": true, "goto": true, "proxy": true, "load": true,
	"fetch": true, "page": true, "site": true, "feed": true,
	"to": true, "out": true, "view": true, "dir": true,
	"show": true, "open": true, "domain": true, "host": true,
	"return_url": true, "redirect_url": true, "callback_url": true,
	"return_to": true, "redirect_to": true, "continue": true,
	"destination": true, "forward": true, "location": true,
}

// takeoverFingerprints maps CNAME targets to potential takeover services.
var takeoverFingerprints = map[string]string{
	"github.io":              "GitHub Pages",
	"herokuapp.com":          "Heroku",
	"herokudns.com":          "Heroku",
	"s3.amazonaws.com":       "AWS S3",
	"s3-website":             "AWS S3",
	"ghost.io":               "Ghost",
	"pantheonsite.io":        "Pantheon",
	"domains.tumblr.com":     "Tumblr",
	"wpengine.com":           "WP Engine",
	"desk.com":               "Desk",
	"zendesk.com":            "Zendesk",
	"teamwork.com":           "Teamwork",
	"helpjuice.com":          "HelpJuice",
	"helpscoutdocs.com":      "HelpScout",
	"feedpress.me":           "FeedPress",
	"freshdesk.com":          "Freshdesk",
	"statuspage.io":          "StatusPage",
	"squarespace.com":        "Squarespace",
	"webflow.io":             "Webflow",
	"fly.dev":                "Fly.io",
	"netlify.app":            "Netlify",
	"vercel.app":             "Vercel",
	"surge.sh":               "Surge",
	"bitbucket.io":           "Bitbucket",
	"azurewebsites.net":      "Azure",
	"cloudapp.net":           "Azure",
	"trafficmanager.net":     "Azure Traffic Manager",
	"blob.core.windows.net":  "Azure Blob",
	"unbouncepages.com":      "Unbounce",
	"agilecrm.com":           "Agile CRM",
	"bigcartel.com":          "Bigcartel",
	"cargocollective.com":    "Cargo",
	"getresponse.com":        "GetResponse",
	"readme.io":              "ReadMe",
	"smugmug.com":            "SmugMug",
	"tilda.ws":               "Tilda",
	"uptimerobot.com":        "UptimeRobot",
}

func (c *Collector) Run(ctx context.Context, opts *RunOpts) (*Result, error) {
	outputDir := filepath.Join(opts.WorkDir, "output")
	rawDir := filepath.Join(opts.WorkDir, "raw")
	harDir := filepath.Join(opts.WorkDir, "har")

	target := ReadDomainFromFile(filepath.Join(opts.WorkDir, "input", "domains.txt"))

	// ── Parse all pipeline data ──

	// Host inventory (httpx + naabu merged)
	hosts := buildHostInventory(rawDir)
	hostMap := make(map[string]*llm.HostInfo, len(hosts))
	for i := range hosts {
		hostMap[hosts[i].Host] = &hosts[i]
	}

	// Analyzer findings (regex-based detections)
	findings := loadFindings(filepath.Join(outputDir, "findings.json"))

	// SmartFuzz findings (probe-based detections)
	fuzzFindings := loadFuzzFindings(filepath.Join(outputDir, "fuzz-findings.json"))

	// Endpoints (from discover provider)
	endpoints := loadEndpoints(filepath.Join(outputDir, "endpoints.json"))

	// Auth headers per host (from HAR)
	authMap := extractAuthByHost(harDir)

	// CORS headers from HAR responses
	corsEntries := extractCORSFromHAR(harDir)

	// Error responses from HAR
	harErrors := extractHARErrorResponses(harDir)

	// Build indexes for correlation
	findingsByHost := indexFindingsByHost(findings)
	findingsByFile := indexFindingsByFile(findings)

	// ── Generate investigations ──

	var investigations []llm.Investigation
	invID := 0

	nextID := func() string {
		invID++
		return fmt.Sprintf("INV-%03d", invID)
	}

	investigations = append(investigations, generateIDORInvestigations(nextID, endpoints, hostMap, authMap)...)
	investigations = append(investigations, generateSSRFInvestigations(nextID, endpoints, hostMap)...)
	investigations = append(investigations, generateSecretInvestigations(nextID, findings, hostMap, findingsByFile)...)
	investigations = append(investigations, generateAccessControlInvestigations(nextID, fuzzFindings, authMap, hostMap)...)
	investigations = append(investigations, generateTechVulnInvestigations(nextID, fuzzFindings, hostMap, findingsByHost)...)
	investigations = append(investigations, generateMisconfigInvestigations(nextID, findings, fuzzFindings)...)
	investigations = append(investigations, generateInfoDisclosureInvestigations(nextID, findings)...)
	investigations = append(investigations, generateSubdomainTakeoverInvestigations(nextID, hosts)...)
	investigations = append(investigations, generateCORSHARInvestigations(nextID, corsEntries, authMap)...)
	investigations = append(investigations, generateErrorResponseInvestigations(nextID, harErrors, hostMap, authMap)...)
	investigations = append(investigations, generateAPIVersionInvestigations(nextID, endpoints, hostMap)...)
	investigations = append(investigations, generateUnauthAccessInvestigations(nextID, endpoints, hostMap)...)

	// ── Write investigations.json ──

	os.MkdirAll(filepath.Dir(opts.Output), 0755)
	invPath := filepath.Join(outputDir, "investigations.json")
	invJSON, err := json.MarshalIndent(investigations, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("collector: marshal investigations: %w", err)
	}
	if err := os.WriteFile(invPath, invJSON, 0644); err != nil {
		return nil, fmt.Errorf("collector: write investigations: %w", err)
	}

	// ── Build intelligence report (summary) ──

	report := &llm.IntelligenceReport{
		Target:             target,
		GeneratedAt:        time.Now().UTC().Format(time.RFC3339),
		SubdomainCount:     LineCount(filepath.Join(outputDir, "subdomains.txt")),
		LiveHostCount:      LineCount(filepath.Join(outputDir, "live-hosts.txt")),
		OpenPortCount:      LineCount(filepath.Join(outputDir, "ports.txt")),
		EndpointCount:      LineCount(filepath.Join(outputDir, "endpoints.json")),
		Hosts:              hosts,
		Findings:           findings,
		AttackSurface:      buildAttackSurface(filepath.Join(outputDir, "endpoints.json"), findings, target),
		InvestigationCount: len(investigations),
	}

	reportJSON, err := json.MarshalIndent(report, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("collector: marshal report: %w", err)
	}
	if err := os.WriteFile(opts.Output, reportJSON, 0644); err != nil {
		return nil, fmt.Errorf("collector: write output: %w", err)
	}

	// Write attack-surface.json (subset)
	surfacePath := filepath.Join(outputDir, "attack-surface.json")
	surfaceJSON, _ := json.MarshalIndent(report.AttackSurface, "", "  ")
	os.WriteFile(surfacePath, surfaceJSON, 0644)

	return &Result{
		Count:      len(investigations),
		OutputFile: opts.Output,
		Extra: map[string]any{
			"subdomains":      report.SubdomainCount,
			"live_hosts":      report.LiveHostCount,
			"open_ports":      report.OpenPortCount,
			"endpoints":       report.EndpointCount,
			"findings":        len(findings),
			"fuzz_findings":   len(fuzzFindings),
			"investigations":  len(investigations),
			"hosts_profiled":  len(hosts),
			"cors_from_har":   len(corsEntries),
			"har_errors":      len(harErrors),
		},
	}, nil
}

// ── Data Loaders ──

func loadFuzzFindings(path string) []smartFuzzFinding {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var findings []smartFuzzFinding
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		var ff smartFuzzFinding
		if json.Unmarshal(scanner.Bytes(), &ff) == nil && ff.TemplateID != "" {
			findings = append(findings, ff)
		}
	}
	return findings
}

func loadEndpoints(path string) []Endpoint {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	var endpoints []Endpoint
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		var ep Endpoint
		if json.Unmarshal(scanner.Bytes(), &ep) == nil && ep.URL != "" {
			endpoints = append(endpoints, ep)
		}
	}
	return endpoints
}

// ── Auth Header Extraction from HAR ──

func extractAuthByHost(harDir string) map[string]authInfo {
	result := make(map[string]authInfo)
	harFiles, _ := filepath.Glob(filepath.Join(harDir, "*.har"))

	for _, harFile := range harFiles {
		f, err := os.Open(harFile)
		if err != nil {
			continue
		}
		data, err := io.ReadAll(io.LimitReader(f, 50*1024*1024))
		f.Close()
		if err != nil {
			continue
		}

		var har cdp.HAR
		if json.Unmarshal(data, &har) != nil {
			continue
		}

		for _, entry := range har.Log.Entries {
			parsed, err := url.Parse(entry.Request.URL)
			if err != nil || parsed.Host == "" {
				continue
			}
			host := parsed.Hostname()

			if _, exists := result[host]; exists {
				continue // already found auth for this host
			}

			for _, h := range entry.Request.Headers {
				name := strings.ToLower(h.Name)
				switch {
				case name == "authorization" && strings.HasPrefix(h.Value, "Bearer "):
					sample := h.Value
					if len(sample) > 30 {
						sample = sample[:30] + "..."
					}
					result[host] = authInfo{HasAuth: true, AuthType: "Bearer", Sample: sample}
				case name == "authorization" && strings.HasPrefix(h.Value, "Basic "):
					result[host] = authInfo{HasAuth: true, AuthType: "Basic", Sample: "Basic ***"}
				case name == "authorization":
					sample := h.Value
					if len(sample) > 30 {
						sample = sample[:30] + "..."
					}
					result[host] = authInfo{HasAuth: true, AuthType: "API-Key", Sample: sample}
				case name == "cookie" && len(h.Value) > 10:
					result[host] = authInfo{HasAuth: true, AuthType: "Cookie", Sample: truncateStr(h.Value, 50)}
				case name == "x-api-key" || name == "x-auth-token":
					sample := h.Value
					if len(sample) > 30 {
						sample = sample[:30] + "..."
					}
					result[host] = authInfo{HasAuth: true, AuthType: "API-Key", Sample: sample}
				}
			}
		}
	}
	return result
}

// ── CORS Header Extraction from HAR ──

type corsInfo struct {
	URL              string
	AllowOrigin      string
	AllowCredentials bool
	Host             string
}

func extractCORSFromHAR(harDir string) []corsInfo {
	var results []corsInfo
	seen := make(map[string]bool)

	harFiles, _ := filepath.Glob(filepath.Join(harDir, "*.har"))
	for _, harFile := range harFiles {
		data, err := os.ReadFile(harFile)
		if err != nil {
			continue
		}
		var har cdp.HAR
		if json.Unmarshal(data, &har) != nil {
			continue
		}

		for _, entry := range har.Log.Entries {
			host := extractHostFromURL(entry.Request.URL)
			if host == "" || seen[host] {
				continue
			}

			var acao, acac string
			for _, h := range entry.Response.Headers {
				switch strings.ToLower(h.Name) {
				case "access-control-allow-origin":
					acao = h.Value
				case "access-control-allow-credentials":
					acac = h.Value
				}
			}
			if acao == "" {
				continue
			}

			// Only flag interesting CORS configurations
			isInteresting := acao == "*" || acao == "null" || strings.EqualFold(acac, "true")
			if !isInteresting {
				continue
			}

			seen[host] = true
			results = append(results, corsInfo{
				URL:              entry.Request.URL,
				AllowOrigin:      acao,
				AllowCredentials: strings.EqualFold(acac, "true"),
				Host:             host,
			})
		}
	}
	return results
}

// ── HAR Error Response Extraction ──

type harErrorEntry struct {
	URL         string
	Method      string
	Status      int
	BodySnippet string
	Host        string
}

func extractHARErrorResponses(harDir string) []harErrorEntry {
	var results []harErrorEntry
	seen := make(map[string]bool)

	harFiles, _ := filepath.Glob(filepath.Join(harDir, "*.har"))
	for _, harFile := range harFiles {
		data, err := os.ReadFile(harFile)
		if err != nil {
			continue
		}
		var har cdp.HAR
		if json.Unmarshal(data, &har) != nil {
			continue
		}

		for _, entry := range har.Log.Entries {
			status := entry.Response.Status
			if status < 400 || status == 404 {
				continue
			}

			key := entry.Request.Method + " " + entry.Request.URL
			if seen[key] {
				continue
			}
			seen[key] = true

			bodySnippet := ""
			if entry.Response.Content.Text != "" {
				bodySnippet = truncateStr(entry.Response.Content.Text, 300)
			}

			results = append(results, harErrorEntry{
				URL:         entry.Request.URL,
				Method:      entry.Request.Method,
				Status:      status,
				BodySnippet: bodySnippet,
				Host:        extractHostFromURL(entry.Request.URL),
			})
		}
	}
	return results
}

// ── Correlation Indexes ──

func indexFindingsByHost(findings []llm.FindingSummary) map[string][]llm.FindingSummary {
	idx := make(map[string][]llm.FindingSummary)
	for _, f := range findings {
		host := extractHostFromURL(f.URL)
		if host == "" {
			host = extractHostFromURL(f.File)
		}
		if host != "" {
			idx[host] = append(idx[host], f)
		}
	}
	return idx
}

func indexFindingsByFile(findings []llm.FindingSummary) map[string][]llm.FindingSummary {
	idx := make(map[string][]llm.FindingSummary)
	for _, f := range findings {
		if f.File != "" {
			idx[f.File] = append(idx[f.File], f)
		}
	}
	return idx
}

func extractHostFromURL(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return ""
	}
	return parsed.Hostname()
}

// ── Investigation Generators ──

// generateIDORInvestigations finds endpoints with parameterized IDs.
func generateIDORInvestigations(nextID func() string, endpoints []Endpoint, hostMap map[string]*llm.HostInfo, authMap map[string]authInfo) []llm.Investigation {
	// Group endpoints by normalized path pattern
	type patternGroup struct {
		Pattern  string
		Method   string
		Host     string
		Examples []string // original URLs
	}

	groups := make(map[string]*patternGroup)
	for _, ep := range endpoints {
		parsed, err := url.Parse(ep.URL)
		if err != nil || parsed.Host == "" {
			continue
		}

		normalized := normalizePath(parsed.Path)
		if !strings.Contains(normalized, "{N}") && !strings.Contains(normalized, "{uuid}") && !strings.Contains(normalized, "{hash}") {
			continue
		}

		key := ep.Method + " " + parsed.Scheme + "://" + parsed.Host + normalized
		if g, ok := groups[key]; ok {
			if len(g.Examples) < 5 {
				g.Examples = append(g.Examples, ep.URL)
			}
		} else {
			groups[key] = &patternGroup{
				Pattern:  normalized,
				Method:   ep.Method,
				Host:     parsed.Hostname(),
				Examples: []string{ep.URL},
			}
		}
	}

	// Also detect IDOR via enriched query param types
	idParamKeywords := []string{"id", "user", "account", "order", "profile", "member"}
	for _, ep := range endpoints {
		if len(ep.ParamDetails) == 0 {
			continue
		}
		parsed, err := url.Parse(ep.URL)
		if err != nil || parsed.Host == "" {
			continue
		}
		for _, pd := range ep.ParamDetails {
			if pd.Type != "numeric" && pd.Type != "uuid" {
				continue
			}
			if ssrfParamNames[strings.ToLower(pd.Name)] {
				continue
			}
			nameLower := strings.ToLower(pd.Name)
			isIDParam := false
			for _, kw := range idParamKeywords {
				if strings.Contains(nameLower, kw) {
					isIDParam = true
					break
				}
			}
			if !isIDParam {
				continue
			}
			key := ep.Method + " " + parsed.Scheme + "://" + parsed.Host + parsed.Path + "?" + pd.Name
			if _, ok := groups[key]; ok {
				continue
			}
			groups[key] = &patternGroup{
				Pattern:  parsed.Path + "?" + pd.Name + "={" + pd.Type + "}",
				Method:   ep.Method,
				Host:     parsed.Hostname(),
				Examples: []string{ep.URL},
			}
		}
	}

	var investigations []llm.Investigation
	for _, g := range groups {
		if len(g.Examples) < 1 {
			continue
		}

		auth := authMap[g.Host]
		ctx := buildHostContext(g.Host, hostMap, auth)
		confidence := "medium"
		if auth.HasAuth {
			confidence = "high" // auth-gated endpoints are more interesting
		}

		var verifySteps []string
		if strings.Contains(g.Pattern, "{N}") {
			verifySteps = []string{
				fmt.Sprintf("%s %s — Replace ID with 0 or 1, does it return data?", g.Method, g.Examples[0]),
				fmt.Sprintf("%s %s — Increment the ID, does it return another user's data?", g.Method, g.Examples[0]),
			}
			if auth.HasAuth {
				verifySteps = append(verifySteps, fmt.Sprintf("%s %s — Send without Authorization header, is unauthenticated access possible?", g.Method, g.Examples[0]))
			}
		} else {
			verifySteps = []string{
				fmt.Sprintf("%s %s — Replace the ID, does it return different data?", g.Method, g.Examples[0]),
			}
			if auth.HasAuth {
				verifySteps = append(verifySteps, fmt.Sprintf("%s — Try accessing without Authorization header", g.Examples[0]))
			}
		}

		investigations = append(investigations, llm.Investigation{
			ID:          nextID(),
			VulnType:    "idor",
			Confidence:  confidence,
			Severity:    "high",
			Title:       fmt.Sprintf("IDOR Candidate: %s %s", g.Method, g.Pattern),
			Description: fmt.Sprintf("Endpoint uses parameterized IDs, %d distinct values observed. Authorization controls should be verified.", len(g.Examples)),
			FoundAt:     llm.InvestigationSource{Source: "endpoints.json", URL: g.Examples[0], Host: g.Host, Method: g.Method},
			Evidence:    g.Examples,
			Context:     ctx,
			VerifySteps: verifySteps,
			Question:    "This endpoint provides ID-based access. Does it return data for different IDs at the same privilege level? Is unauthenticated access possible?",
		})
	}

	return investigations
}

// generateSSRFInvestigations finds endpoints with URL-like parameters.
func generateSSRFInvestigations(nextID func() string, endpoints []Endpoint, hostMap map[string]*llm.HostInfo) []llm.Investigation {
	var investigations []llm.Investigation
	seen := make(map[string]bool) // deduplicate by host+param

	for _, ep := range endpoints {
		parsed, err := url.Parse(ep.URL)
		if err != nil || parsed.Host == "" {
			continue
		}

		// Check query parameters by name
		for _, param := range ep.Params {
			paramLower := strings.ToLower(param)
			if !ssrfParamNames[paramLower] {
				continue
			}

			key := parsed.Hostname() + "|" + paramLower
			if seen[key] {
				continue
			}
			seen[key] = true

			host := parsed.Hostname()
			ctx := buildHostContext(host, hostMap, authInfo{})

			investigations = append(investigations, llm.Investigation{
				ID:          nextID(),
				VulnType:    "ssrf",
				Confidence:  "medium",
				Severity:    "high",
				Title:       fmt.Sprintf("SSRF Candidate: ?%s= parameter on %s", param, host),
				Description: fmt.Sprintf("Parameter '%s' may accept URL/path values. Potential server-side request forgery risk.", param),
				FoundAt:     llm.InvestigationSource{Source: "endpoints.json", URL: ep.URL, Host: host, Method: ep.Method},
				Evidence:    []string{ep.URL},
				Context:     ctx,
				VerifySteps: []string{
					fmt.Sprintf("?%s=http://127.0.0.1 — Does it make a request to localhost?", param),
					fmt.Sprintf("?%s=http://169.254.169.254/latest/meta-data/ — Is AWS metadata accessible?", param),
					fmt.Sprintf("?%s=http://[burp-collaborator] — Does it trigger an out-of-band callback?", param),
					fmt.Sprintf("?%s=file:///etc/passwd — Is local file read possible?", param),
				},
				Question: fmt.Sprintf("Does parameter '%s' accept URL/path values? Can it access internal services or cloud metadata?", param),
			})
		}

		// Check enriched param types — actual URL value observed
		for _, pd := range ep.ParamDetails {
			if pd.Type != "url" {
				continue
			}
			paramLower := strings.ToLower(pd.Name)
			key := parsed.Hostname() + "|" + paramLower
			if seen[key] {
				continue
			}
			seen[key] = true

			host := parsed.Hostname()
			ctx := buildHostContext(host, hostMap, authInfo{})

			investigations = append(investigations, llm.Investigation{
				ID:          nextID(),
				VulnType:    "ssrf",
				Confidence:  "high",
				Severity:    "high",
				Title:       fmt.Sprintf("SSRF Candidate: ?%s= (URL value observed) on %s", pd.Name, host),
				Description: fmt.Sprintf("Parameter '%s' contains an actual URL value: %s. High SSRF risk.", pd.Name, truncateStr(pd.Value, 80)),
				FoundAt:     llm.InvestigationSource{Source: "endpoints.json", URL: ep.URL, Host: host, Method: ep.Method},
				Evidence:    []string{ep.URL, fmt.Sprintf("Observed value: %s", pd.Value)},
				Context:     ctx,
				VerifySteps: []string{
					fmt.Sprintf("?%s=http://127.0.0.1 — Does it make a request to localhost?", pd.Name),
					fmt.Sprintf("?%s=http://169.254.169.254/latest/meta-data/ — Is AWS metadata accessible?", pd.Name),
					fmt.Sprintf("?%s=http://[burp-collaborator] — Does it trigger an out-of-band callback?", pd.Name),
				},
				Question: fmt.Sprintf("Parameter '%s' accepts URLs (observed value: %s). Can it access internal services or cloud metadata?", pd.Name, truncateStr(pd.Value, 60)),
			})
		}
	}
	return investigations
}

// generateSecretInvestigations creates investigations for exposed secrets.
func generateSecretInvestigations(nextID func() string, findings []llm.FindingSummary, hostMap map[string]*llm.HostInfo, findingsByFile map[string][]llm.FindingSummary) []llm.Investigation {
	var investigations []llm.Investigation

	for _, f := range findings {
		if f.Severity != "critical" && f.Severity != "high" {
			continue
		}
		if !isSecretFinding(f.RuleID) {
			continue
		}

		host := extractHostFromURL(f.URL)
		ctx := buildHostContext(host, hostMap, authInfo{})

		// Cross-correlate: other findings in the same file
		if sameFile := findingsByFile[f.File]; len(sameFile) > 1 {
			for _, sf := range sameFile {
				if sf.RuleID != f.RuleID {
					ctx.SameFileFindings = append(ctx.SameFileFindings, sf.RuleID+": "+truncateStr(sf.Value, 60))
				}
			}
		}

		verifySteps := buildSecretVerifySteps(f)
		evidence := []string{truncateStr(f.Value, 100)}

		investigations = append(investigations, llm.Investigation{
			ID:          nextID(),
			VulnType:    "exposed_secret",
			Confidence:  "high",
			Severity:    f.Severity,
			Title:       fmt.Sprintf("%s: %s", f.RuleName, truncateStr(f.Value, 40)),
			Description: fmt.Sprintf("%s found. Source: %s", f.RuleName, f.Source),
			FoundAt:     llm.InvestigationSource{Source: f.Source, File: f.File, URL: f.URL, Host: host, Line: 0},
			Evidence:    evidence,
			Context:     ctx,
			VerifySteps: verifySteps,
			Question:    fmt.Sprintf("Is this %s active and usable? Are there other credentials in the same source?", f.RuleName),
		})
	}
	return investigations
}

// generateAccessControlInvestigations finds admin/debug endpoints accessible without auth.
func generateAccessControlInvestigations(nextID func() string, fuzzFindings []smartFuzzFinding, authMap map[string]authInfo, hostMap map[string]*llm.HostInfo) []llm.Investigation {
	var investigations []llm.Investigation

	// Admin/debug paths found by smartfuzz
	accessKeywords := []string{"admin", "manage", "debug", "internal", "console", "dashboard", "settings", "config"}

	for _, ff := range fuzzFindings {
		matchedAt := strings.ToLower(ff.MatchedAt)
		isAdmin := false
		for _, kw := range accessKeywords {
			if strings.Contains(matchedAt, kw) {
				isAdmin = true
				break
			}
		}
		if !isAdmin {
			continue
		}

		host := extractHostFromURL(ff.Host)
		auth := authMap[host]
		ctx := buildHostContext(host, hostMap, auth)

		confidence := "medium"
		if !auth.HasAuth {
			confidence = "high" // no auth seen at all for this host
		}

		investigations = append(investigations, llm.Investigation{
			ID:          nextID(),
			VulnType:    "access_control",
			Confidence:  confidence,
			Severity:    ff.Severity,
			Title:       fmt.Sprintf("Access Control: %s", ff.Name),
			Description: fmt.Sprintf("Admin/debug endpoint accessible: %s. Detected by SmartFuzz.", ff.MatchedAt),
			FoundAt:     llm.InvestigationSource{Source: "fuzz-findings.json", URL: ff.MatchedAt, Host: host},
			Evidence:    []string{ff.Evidence},
			Context:     ctx,
			VerifySteps: []string{
				fmt.Sprintf("GET %s — Is it accessible without Authorization header?", ff.MatchedAt),
				"Try modifying/creating data with a POST request",
				"Try accessing with a different user role",
			},
			Question: "Is this admin/debug endpoint publicly accessible? Can sensitive data or functions be accessed without authorization?",
		})
	}
	return investigations
}

// generateTechVulnInvestigations creates investigations from smartfuzz findings.
func generateTechVulnInvestigations(nextID func() string, fuzzFindings []smartFuzzFinding, hostMap map[string]*llm.HostInfo, findingsByHost map[string][]llm.FindingSummary) []llm.Investigation {
	var investigations []llm.Investigation

	// Skip access_control findings (handled separately) and info severity
	accessKeywords := []string{"admin", "manage", "debug", "internal", "console", "dashboard", "settings", "config"}

	for _, ff := range fuzzFindings {
		if ff.Severity == "info" {
			continue
		}

		// Skip if already handled by access_control generator
		matchedLower := strings.ToLower(ff.MatchedAt)
		isAdmin := false
		for _, kw := range accessKeywords {
			if strings.Contains(matchedLower, kw) {
				isAdmin = true
				break
			}
		}
		if isAdmin {
			continue
		}

		host := extractHostFromURL(ff.Host)
		ctx := buildHostContext(host, hostMap, authInfo{})

		// Add same-host findings for correlation
		if hostFindings := findingsByHost[host]; len(hostFindings) > 0 {
			for _, hf := range hostFindings {
				ctx.SameHostFindings = append(ctx.SameHostFindings, hf.RuleID)
				if len(ctx.SameHostFindings) >= 10 {
					break
				}
			}
		}

		verifySteps := buildTechVulnVerifySteps(ff)

		investigations = append(investigations, llm.Investigation{
			ID:          nextID(),
			VulnType:    "tech_vuln",
			Confidence:  "high",
			Severity:    ff.Severity,
			Title:       ff.Name,
			Description: ff.Description,
			FoundAt:     llm.InvestigationSource{Source: "fuzz-findings.json", URL: ff.MatchedAt, Host: host},
			Evidence:    []string{ff.Evidence},
			Context:     ctx,
			VerifySteps: verifySteps,
			Question:    fmt.Sprintf("Is %s actually accessible? Does it leak sensitive data? Is it exploitable?", ff.Name),
		})
	}
	return investigations
}

// generateMisconfigInvestigations creates investigations for CORS and header misconfigurations.
func generateMisconfigInvestigations(nextID func() string, findings []llm.FindingSummary, fuzzFindings []smartFuzzFinding) []llm.Investigation {
	var investigations []llm.Investigation

	// CORS findings from smartfuzz
	for _, ff := range fuzzFindings {
		if ff.Source != "cors" {
			continue
		}

		host := extractHostFromURL(ff.Host)
		investigations = append(investigations, llm.Investigation{
			ID:          nextID(),
			VulnType:    "misconfiguration",
			Confidence:  "high",
			Severity:    ff.Severity,
			Title:       ff.Name,
			Description: ff.Description,
			FoundAt:     llm.InvestigationSource{Source: "fuzz-findings.json", URL: ff.MatchedAt, Host: host},
			Evidence:    []string{ff.Evidence},
			Context:     llm.InvestigationContext{},
			VerifySteps: []string{
				"Can cookies/tokens be read from an evil origin?",
				"Is CORS reflection present on state-changing endpoints (POST/PUT/DELETE)?",
				"Can it be used with credentials?",
			},
			Question: "Is this CORS misconfiguration exploitable? Can sensitive data or session tokens be stolen?",
		})
	}

	// Header misconfigurations from analyzer
	for _, f := range findings {
		if f.Source != "har_headers" {
			continue
		}
		if f.Severity == "info" || f.Severity == "low" {
			continue
		}

		host := extractHostFromURL(f.URL)
		investigations = append(investigations, llm.Investigation{
			ID:          nextID(),
			VulnType:    "misconfiguration",
			Confidence:  "medium",
			Severity:    f.Severity,
			Title:       f.RuleName,
			Description: fmt.Sprintf("HTTP header misconfiguration: %s", f.Value),
			FoundAt:     llm.InvestigationSource{Source: "findings.json", URL: f.URL, Host: host},
			Evidence:    []string{f.Value},
			Context:     llm.InvestigationContext{},
			VerifySteps: []string{
				fmt.Sprintf("Verify header: curl -I %s", f.URL),
				"Is the same issue present across all endpoints?",
				"Is there an exploitable impact?",
			},
			Question: fmt.Sprintf("Is %s exploitable? Does it have a real security impact?", f.RuleName),
		})
	}
	return investigations
}

// generateInfoDisclosureInvestigations creates investigations for SQL errors, stack traces, etc.
func generateInfoDisclosureInvestigations(nextID func() string, findings []llm.FindingSummary) []llm.Investigation {
	var investigations []llm.Investigation

	infoRules := map[string]struct {
		vulnHint    string
		verifySteps []string
	}{
		"sql-error": {
			vulnHint: "SQL Injection",
			verifySteps: []string{
				"Append ' (single quote) to URL parameter — does the SQL error change?",
				"Try ' OR 1=1-- — does it return different results?",
				"Try ' UNION SELECT NULL-- — determine column count",
				"Run automated testing with sqlmap",
			},
		},
		"error-stack-trace": {
			vulnHint: "Information Disclosure via Stack Trace",
			verifySteps: []string{
				"Does the stack trace reveal framework version, internal paths, or credentials?",
				"Can more traces be triggered with different inputs?",
				"Error handling is improper — test other endpoints as well",
			},
		},
		"internal-ip": {
			vulnHint: "Internal Network Mapping",
			verifySteps: []string{
				"Does the internal IP appear in other responses?",
				"Is direct access to this IP possible (via SSRF)?",
				"Can the network topology be mapped?",
			},
		},
	}

	for _, f := range findings {
		rule, ok := infoRules[f.RuleID]
		if !ok {
			continue
		}

		host := extractHostFromURL(f.URL)
		confidence := "high"
		if f.RuleID == "internal-ip" {
			confidence = "medium"
		}

		investigations = append(investigations, llm.Investigation{
			ID:          nextID(),
			VulnType:    "info_disclosure",
			Confidence:  confidence,
			Severity:    f.Severity,
			Title:       fmt.Sprintf("%s — Potential %s", f.RuleName, rule.vulnHint),
			Description: fmt.Sprintf("%s detected. This may indicate a %s vulnerability.", f.RuleName, rule.vulnHint),
			FoundAt:     llm.InvestigationSource{Source: f.Source, URL: f.URL, Host: host, File: f.File},
			Evidence:    []string{truncateStr(f.Value, 200)},
			Context:     llm.InvestigationContext{},
			VerifySteps: rule.verifySteps,
			Question:    fmt.Sprintf("Is %s a real vulnerability indicator? Can it be actively exploited?", rule.vulnHint),
		})
	}
	return investigations
}

// generateSubdomainTakeoverInvestigations checks CNAME records for dangling references.
func generateSubdomainTakeoverInvestigations(nextID func() string, hosts []llm.HostInfo) []llm.Investigation {
	var investigations []llm.Investigation

	for _, h := range hosts {
		if len(h.CNAME) == 0 {
			continue
		}

		for _, cname := range h.CNAME {
			cnameLower := strings.ToLower(cname)
			for fingerprint, service := range takeoverFingerprints {
				if !strings.Contains(cnameLower, fingerprint) {
					continue
				}

				// Check if host returned error-like status
				confidence := "low"
				if h.StatusCode == 404 || h.StatusCode == 0 {
					confidence = "high"
				} else if h.StatusCode >= 400 {
					confidence = "medium"
				}

				investigations = append(investigations, llm.Investigation{
					ID:          nextID(),
					VulnType:    "subdomain_takeover",
					Confidence:  confidence,
					Severity:    "high",
					Title:       fmt.Sprintf("Subdomain Takeover: %s → %s (%s)", h.Host, cname, service),
					Description: fmt.Sprintf("CNAME points to %s service (%s). Status: %d. Can the service be claimed?", service, cname, h.StatusCode),
					FoundAt:     llm.InvestigationSource{Source: "httpx", Host: h.Host},
					Evidence:    []string{fmt.Sprintf("CNAME: %s", cname), fmt.Sprintf("Status: %d", h.StatusCode)},
					Context:     llm.InvestigationContext{},
					VerifySteps: []string{
						fmt.Sprintf("dig %s CNAME — Is the CNAME still active?", h.Host),
						fmt.Sprintf("curl -I https://%s — What does the response return?", h.Host),
						fmt.Sprintf("Try claiming '%s' on %s", h.Host, service),
					},
					Question: fmt.Sprintf("Is the CNAME on %s dangling? Is subdomain takeover possible via %s?", h.Host, service),
				})
				break // one match per CNAME is enough
			}
		}
	}
	return investigations
}

// generateCORSHARInvestigations creates investigations from CORS headers observed in HAR.
func generateCORSHARInvestigations(nextID func() string, corsEntries []corsInfo, authMap map[string]authInfo) []llm.Investigation {
	var investigations []llm.Investigation
	for _, c := range corsEntries {
		auth := authMap[c.Host]

		severity := "medium"
		desc := fmt.Sprintf("CORS allows origin: %s", c.AllowOrigin)
		if c.AllowCredentials && (c.AllowOrigin == "*" || c.AllowOrigin == "null") {
			severity = "high"
			desc = "CORS allows credentials with wildcard/null origin — cookie theft possible"
		}

		investigations = append(investigations, llm.Investigation{
			ID:          nextID(),
			VulnType:    "misconfiguration",
			Confidence:  "high",
			Severity:    severity,
			Title:       fmt.Sprintf("CORS Misconfiguration (HAR): %s", c.Host),
			Description: desc,
			FoundAt:     llm.InvestigationSource{Source: "har", URL: c.URL, Host: c.Host},
			Evidence: []string{
				fmt.Sprintf("Access-Control-Allow-Origin: %s", c.AllowOrigin),
				fmt.Sprintf("Access-Control-Allow-Credentials: %v", c.AllowCredentials),
			},
			Context: llm.InvestigationContext{AuthSeen: auth.HasAuth, AuthType: auth.AuthType},
			VerifySteps: []string{
				fmt.Sprintf("curl -H 'Origin: https://evil.test' -I %s — Is there origin reflection?", c.URL),
				"Can cookies/tokens be read from an evil origin?",
				"Is CORS reflection present on state-changing endpoints (POST/PUT/DELETE)?",
			},
			Question: "Is this CORS misconfiguration exploitable? Can sensitive data or session tokens be stolen?",
		})
	}
	return investigations
}

// generateErrorResponseInvestigations creates investigations from 4xx/5xx HAR responses.
func generateErrorResponseInvestigations(nextID func() string, errors []harErrorEntry, hostMap map[string]*llm.HostInfo, authMap map[string]authInfo) []llm.Investigation {
	var investigations []llm.Investigation

	for _, e := range errors {
		ctx := buildHostContext(e.Host, hostMap, authMap[e.Host])

		switch {
		case e.Status == 403:
			investigations = append(investigations, llm.Investigation{
				ID:          nextID(),
				VulnType:    "access_control",
				Confidence:  "medium",
				Severity:    "medium",
				Title:       fmt.Sprintf("403 Forbidden — Auth Bypass Candidate: %s %s", e.Method, e.URL),
				Description: "Endpoint returns 403. Can it be bypassed with different auth methods or header manipulation?",
				FoundAt:     llm.InvestigationSource{Source: "har", URL: e.URL, Host: e.Host, Method: e.Method},
				Evidence:    []string{fmt.Sprintf("%d Forbidden", e.Status), e.BodySnippet},
				Context:     ctx,
				VerifySteps: []string{
					fmt.Sprintf("%s %s — Try without Authorization header", e.Method, e.URL),
					fmt.Sprintf("%s %s — Switch HTTP method (GET<->POST)", e.Method, e.URL),
					fmt.Sprintf("%s %s — Add X-Forwarded-For: 127.0.0.1 header", e.Method, e.URL),
					fmt.Sprintf("%s %s — Try path traversal: /..;/path", e.Method, e.URL),
				},
				Question: "Can this 403 endpoint be bypassed? Is access possible via different HTTP methods, headers, or path manipulation?",
			})

		case e.Status == 401:
			investigations = append(investigations, llm.Investigation{
				ID:          nextID(),
				VulnType:    "access_control",
				Confidence:  "low",
				Severity:    "low",
				Title:       fmt.Sprintf("401 Unauthorized — Auth Required: %s %s", e.Method, e.URL),
				Description: "Endpoint requires authentication. Access can be attempted with another user's token.",
				FoundAt:     llm.InvestigationSource{Source: "har", URL: e.URL, Host: e.Host, Method: e.Method},
				Evidence:    []string{fmt.Sprintf("%d Unauthorized", e.Status)},
				Context:     ctx,
				VerifySteps: []string{
					"Try accessing with a different session/token",
					"Try default credentials",
				},
				Question: "Is unauthorized access to this endpoint possible?",
			})

		case e.Status >= 500:
			confidence := "medium"
			if e.BodySnippet != "" {
				confidence = "high"
			}
			investigations = append(investigations, llm.Investigation{
				ID:          nextID(),
				VulnType:    "info_disclosure",
				Confidence:  confidence,
				Severity:    "medium",
				Title:       fmt.Sprintf("Server Error %d — Potential Injection Point: %s %s", e.Status, e.Method, e.URL),
				Description: fmt.Sprintf("Endpoint returns %d. Possible input handling error, candidate for injection testing.", e.Status),
				FoundAt:     llm.InvestigationSource{Source: "har", URL: e.URL, Host: e.Host, Method: e.Method},
				Evidence:    []string{fmt.Sprintf("%d Server Error", e.Status), e.BodySnippet},
				Context:     ctx,
				VerifySteps: []string{
					fmt.Sprintf("%s %s — Append ' to parameters, does a SQL error appear?", e.Method, e.URL),
					fmt.Sprintf("%s %s — Append {{7*7}} to parameters, is template injection present?", e.Method, e.URL),
					fmt.Sprintf("%s %s — Send large input, is there a buffer overflow?", e.Method, e.URL),
				},
				Question: "Is this 500 error caused by input manipulation? Is there an injection vulnerability?",
			})
		}
	}
	return investigations
}

// generateAPIVersionInvestigations checks for API version escalation opportunities.
func generateAPIVersionInvestigations(nextID func() string, endpoints []Endpoint, hostMap map[string]*llm.HostInfo) []llm.Investigation {
	var investigations []llm.Investigation
	seen := make(map[string]bool)

	for _, ep := range endpoints {
		if ep.APIVersion == "" || ep.NextVersion == "" {
			continue
		}
		parsed, err := url.Parse(ep.URL)
		if err != nil || parsed.Host == "" {
			continue
		}
		key := parsed.Hostname() + "|" + ep.APIVersion
		if seen[key] {
			continue
		}
		seen[key] = true

		host := parsed.Hostname()
		nextURL := strings.Replace(ep.URL, "/"+ep.APIVersion+"/", "/"+ep.NextVersion+"/", 1)
		ctx := buildHostContext(host, hostMap, authInfo{})

		investigations = append(investigations, llm.Investigation{
			ID:          nextID(),
			VulnType:    "info_disclosure",
			Confidence:  "low",
			Severity:    "info",
			Title:       fmt.Sprintf("API Version %s Found — Try %s on %s", ep.APIVersion, ep.NextVersion, host),
			Description: fmt.Sprintf("API %s is in use. %s may exist and could have different authorization rules.", ep.APIVersion, ep.NextVersion),
			FoundAt:     llm.InvestigationSource{Source: "endpoints.json", URL: ep.URL, Host: host, Method: ep.Method},
			Evidence:    []string{ep.URL},
			Context:     ctx,
			VerifySteps: []string{
				fmt.Sprintf("GET %s — Is the new version accessible?", nextURL),
				fmt.Sprintf("Older version (%s) may bypass deprecated security controls", ep.APIVersion),
			},
			Question: fmt.Sprintf("Does version %s exist? Does it have different or weaker authorization rules?", ep.NextVersion),
		})
	}
	return investigations
}

// generateUnauthAccessInvestigations creates an investigation for every non-static
// endpoint discovered via unauthenticated JS/HAR crawling. The AI agent decides
// what's testable and what vulnerabilities to look for based on the endpoint context.
func generateUnauthAccessInvestigations(nextID func() string, endpoints []Endpoint, hostMap map[string]*llm.HostInfo) []llm.Investigation {
	var investigations []llm.Investigation
	seen := make(map[string]bool)

	for _, ep := range endpoints {
		parsed, err := url.Parse(ep.URL)
		if err != nil || parsed.Host == "" {
			continue
		}

		pathLower := strings.ToLower(parsed.Path)
		if pathLower == "" || pathLower == "/" {
			continue
		}

		// Skip static assets
		if isStaticAsset(pathLower) {
			continue
		}

		// Dedup by host + normalized path
		host := parsed.Hostname()
		key := host + "|" + normalizePath(parsed.Path)
		if seen[key] {
			continue
		}
		seen[key] = true

		ctx := buildHostContext(host, hostMap, authInfo{})

		// Build evidence from enriched endpoint data
		var evidence []string
		evidence = append(evidence, fmt.Sprintf("Source: %s", ep.Source))
		if ep.SourceFile != "" {
			evidence = append(evidence, fmt.Sprintf("File: %s", ep.SourceFile))
		}
		if len(ep.Params) > 0 {
			evidence = append(evidence, fmt.Sprintf("Params: %s", strings.Join(ep.Params, ", ")))
		}
		if len(ep.ParamDetails) > 0 {
			for _, pd := range ep.ParamDetails {
				evidence = append(evidence, fmt.Sprintf("Param %s=%s (type: %s)", pd.Name, truncateStr(pd.Value, 50), pd.Type))
			}
		}
		if len(ep.BodyFields) > 0 {
			evidence = append(evidence, fmt.Sprintf("POST body fields: %s", strings.Join(ep.BodyFields, ", ")))
		}
		if len(ep.ResponseFields) > 0 {
			evidence = append(evidence, fmt.Sprintf("Response fields: %s", strings.Join(ep.ResponseFields, ", ")))
		}
		if ep.StatusCode > 0 {
			evidence = append(evidence, fmt.Sprintf("Status: %d", ep.StatusCode))
		}
		if ep.Context != "" {
			evidence = append(evidence, fmt.Sprintf("Context: %s", truncateStr(ep.Context, 100)))
		}

		investigations = append(investigations, llm.Investigation{
			ID:       nextID(),
			VulnType: "unauth_endpoint",
			Confidence: "low",
			Severity:   "info",
			Title:      fmt.Sprintf("Endpoint Discovered: %s %s", ep.Method, parsed.Path),
			Description: fmt.Sprintf(
				"This endpoint was discovered unauthenticated from %s source. "+
					"Evaluate whether it is a valid endpoint, if it is accessible, and what security tests can be applied.",
				ep.Source,
			),
			FoundAt: llm.InvestigationSource{
				Source: ep.Source,
				URL:    ep.URL,
				Host:   host,
				Method: ep.Method,
				File:   ep.SourceFile,
			},
			Evidence: evidence,
			Context:  ctx,
			VerifySteps: []string{
				fmt.Sprintf("curl -s -o /dev/null -w '%%{http_code}' %s — Is the endpoint accessible?", ep.URL),
				"Inspect the response: does it return data, what type of data?",
				"Does it require auth? Is unauthenticated access a broken access control issue?",
				"If it has parameters: can IDOR, SSRF, or injection tests be applied?",
			},
			Question: "Is this endpoint valid and accessible? What security tests should be performed? Is unauthenticated access a vulnerability?",
		})
	}
	return investigations
}

// isStaticAsset checks if a path looks like a static file.
func isStaticAsset(pathLower string) bool {
	staticExts := []string{
		".js", ".css", ".png", ".jpg", ".jpeg", ".gif", ".svg", ".ico",
		".woff", ".woff2", ".ttf", ".eot", ".map", ".webp", ".avif",
		".mp4", ".webm", ".pdf",
	}
	for _, ext := range staticExts {
		if strings.HasSuffix(pathLower, ext) {
			return true
		}
	}
	staticPaths := []string{"/static/", "/assets/", "/public/", "/dist/", "/build/", "/_next/static/", "/cdn-cgi/"}
	for _, p := range staticPaths {
		if strings.Contains(pathLower, p) {
			return true
		}
	}
	return false
}

// ── Helper Functions ──

func buildHostContext(host string, hostMap map[string]*llm.HostInfo, auth authInfo) llm.InvestigationContext {
	ctx := llm.InvestigationContext{
		AuthSeen: auth.HasAuth,
		AuthType: auth.AuthType,
	}
	if h, ok := hostMap[host]; ok {
		ctx.HostTech = h.Tech
		ctx.HostCDN = h.CDN
		ctx.HostServer = h.Server
	}
	return ctx
}

func isSecretFinding(ruleID string) bool {
	secretRules := []string{
		"aws-access-key", "aws-secret-key", "github-token", "github-fine-grained",
		"gitlab-token", "slack-token", "slack-webhook", "stripe-secret",
		"twilio-api-key", "sendgrid-api-key", "firebase-api-key",
		"jwt-token", "private-key", "basic-auth-url",
		"generic-api-key", "generic-secret", "discord-webhook", "telegram-bot-token",
		"heroku-api-key", "mailgun-api-key", "mapbox-token",
		"anthropic-api-key", "openai-api-key-v2", "huggingface-token",
		"replicate-api-token", "cohere-api-key", "groq-api-key", "together-api-key",
		"vercel-token", "supabase-service-key", "planetscale-token",
		"neon-api-key", "railway-token", "linear-api-key", "doppler-token", "postman-api-key",
		"azure-sas-token",
	}
	for _, r := range secretRules {
		if ruleID == r {
			return true
		}
	}
	return false
}

func buildSecretVerifySteps(f llm.FindingSummary) []string {
	switch {
	case strings.Contains(f.RuleID, "aws"):
		return []string{
			"Validate key with AWS CLI: aws sts get-caller-identity --access-key-id [KEY]",
			"Is there an AWS secret key in the same file?",
			"Try S3 bucket access: aws s3 ls --profile test",
		}
	case strings.Contains(f.RuleID, "github"):
		return []string{
			"Check token scope: curl -H 'Authorization: token [TOKEN]' https://api.github.com/user",
			"Which repos does it have access to?",
			"Does the token have org-level permissions?",
		}
	case f.RuleID == "jwt-token":
		return []string{
			"Decode the JWT at jwt.io — what's in the payload?",
			"Try signature verification bypass (alg: none)",
			"Is the token expired? Try access with a non-expired token",
		}
	case f.RuleID == "private-key":
		return []string{
			"Check key type and size",
			"Which service uses this key?",
			"Try SSH or TLS connection with the key",
		}
	case strings.Contains(f.RuleID, "stripe"):
		return []string{
			"Validate key with Stripe API: curl https://api.stripe.com/v1/charges -u [KEY]:",
			"Is it a live key or test key?",
			"Is there access to payment data?",
		}
	default:
		return []string{
			"Verify whether the key/token is active",
			"Are there other credentials in the same source?",
			"Check token scope and permissions",
		}
	}
}

func buildTechVulnVerifySteps(ff smartFuzzFinding) []string {
	tid := strings.ToLower(ff.TemplateID)
	switch {
	case strings.Contains(tid, "actuator-env"):
		return []string{
			"Does the response contain plaintext passwords or API keys?",
			"Can /actuator/heapdump be downloaded?",
			"Can properties be set via POST /actuator/env? (RCE chain)",
		}
	case strings.Contains(tid, "heapdump"):
		return []string{
			"Download heapdump and search for credentials: strings heapdump | grep -i password",
			"Analyze with JVisualVM or Eclipse MAT",
			"Search for database connection strings, API keys",
		}
	case strings.Contains(tid, "pprof"):
		return []string{
			"Search heap dump for credentials/secrets",
			"Search goroutine dump for internal API paths",
			"Check startup arguments via /debug/pprof/cmdline",
		}
	case strings.Contains(tid, "graphql"):
		return []string{
			"List all types and queries via introspection",
			"Are there mutations? Check authorization",
			"Search for sensitive fields (password, token, secret)",
		}
	case strings.Contains(tid, "git"):
		return []string{
			"Download the entire .git/ directory with git-dumper",
			"Search source code for hardcoded credentials",
			"Search commit history for deleted secrets: git log -p | grep -i password",
		}
	case strings.Contains(tid, "env"):
		return []string{
			"Validate credentials in the .env file",
			"Try connecting with the database connection string",
			"Check API key scopes and permissions",
		}
	default:
		return []string{
			fmt.Sprintf("Verify endpoint access: curl %s", ff.MatchedAt),
			"Check if sensitive data is leaking",
			"Assess whether it is exploitable",
		}
	}
}

func truncateStr(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen] + "..."
}

// ── Existing functions (reused from original collector) ──

func buildHostInventory(rawDir string) []llm.HostInfo {
	hosts := make(map[string]*llm.HostInfo)

	getHost := func(name string) *llm.HostInfo {
		if h, ok := hosts[name]; ok {
			return h
		}
		h := &llm.HostInfo{Host: name}
		hosts[name] = h
		return h
	}

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
			Server     string   `json:"server"`
			TLS        *struct {
				Version  string `json:"tls_version"`
				IssuerCN string `json:"issuer_cn"`
				NotAfter string `json:"not_after"`
				Wildcard bool   `json:"wildcard_certificate"`
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
		if entry.Server != "" {
			h.Server = entry.Server
		}
		if entry.TLS != nil {
			h.TLSVersion = entry.TLS.Version
			h.TLSIssuer = entry.TLS.IssuerCN
			h.TLSExpiry = entry.TLS.NotAfter
			h.Wildcard = entry.TLS.Wildcard
		}
	})

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
