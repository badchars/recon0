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

	var investigations []llm.Investigation
	for _, g := range groups {
		if len(g.Examples) < 2 {
			continue // need at least 2 examples to suggest IDOR
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
				fmt.Sprintf("%s %s — ID'yi 0 veya 1 ile değiştir, veri dönüyor mu?", g.Method, g.Examples[0]),
				fmt.Sprintf("%s %s — ID'yi bir artır, başka kullanıcının verisi dönüyor mu?", g.Method, g.Examples[0]),
			}
			if auth.HasAuth {
				verifySteps = append(verifySteps, fmt.Sprintf("%s %s — Authorization header olmadan gönder, unauth erişim var mı?", g.Method, g.Examples[0]))
			}
		} else {
			verifySteps = []string{
				fmt.Sprintf("%s %s — ID'yi değiştir, farklı veri dönüyor mu?", g.Method, g.Examples[0]),
			}
			if auth.HasAuth {
				verifySteps = append(verifySteps, fmt.Sprintf("%s — Authorization olmadan erişim dene", g.Examples[0]))
			}
		}

		investigations = append(investigations, llm.Investigation{
			ID:          nextID(),
			VulnType:    "idor",
			Confidence:  confidence,
			Severity:    "high",
			Title:       fmt.Sprintf("IDOR Candidate: %s %s", g.Method, g.Pattern),
			Description: fmt.Sprintf("Endpoint parameterized ID kullanıyor, %d farklı değer gözlemlendi. Yetkilendirme kontrolü doğrulanmalı.", len(g.Examples)),
			FoundAt:     llm.InvestigationSource{Source: "endpoints.json", URL: g.Examples[0], Host: g.Host, Method: g.Method},
			Evidence:    g.Examples,
			Context:     ctx,
			VerifySteps: verifySteps,
			Question:    "Bu endpoint ID tabanlı erişim sağlıyor. Farklı ID'lerle aynı yetki seviyesinde veri dönüyor mu? Authorization olmadan erişim mümkün mü?",
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

		// Check query parameters
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
				Description: fmt.Sprintf("Endpoint'te '%s' parametresi URL/path kabul ediyor olabilir. Server-side request forgery riski.", param),
				FoundAt:     llm.InvestigationSource{Source: "endpoints.json", URL: ep.URL, Host: host, Method: ep.Method},
				Evidence:    []string{ep.URL},
				Context:     ctx,
				VerifySteps: []string{
					fmt.Sprintf("?%s=http://127.0.0.1 — localhost'a istek gidiyor mu?", param),
					fmt.Sprintf("?%s=http://169.254.169.254/latest/meta-data/ — AWS metadata erişimi var mı?", param),
					fmt.Sprintf("?%s=http://[burp-collaborator] — out-of-band callback dönüyor mu?", param),
					fmt.Sprintf("?%s=file:///etc/passwd — local file read mümkün mü?", param),
				},
				Question: fmt.Sprintf("'%s' parametresi URL/path kabul ediyor mu? Internal servislere veya cloud metadata'ya erişim sağlanabiliyor mu?", param),
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
			Description: fmt.Sprintf("%s bulundu. Kaynak: %s", f.RuleName, f.Source),
			FoundAt:     llm.InvestigationSource{Source: f.Source, File: f.File, URL: f.URL, Host: host, Line: 0},
			Evidence:    evidence,
			Context:     ctx,
			VerifySteps: verifySteps,
			Question:    fmt.Sprintf("Bu %s aktif ve kullanılabilir mi? Aynı kaynakta başka credential var mı?", f.RuleName),
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
			Description: fmt.Sprintf("Admin/debug endpoint erişilebilir: %s. SmartFuzz tarafından tespit edildi.", ff.MatchedAt),
			FoundAt:     llm.InvestigationSource{Source: "fuzz-findings.json", URL: ff.MatchedAt, Host: host},
			Evidence:    []string{ff.Evidence},
			Context:     ctx,
			VerifySteps: []string{
				fmt.Sprintf("GET %s — Authorization header olmadan erişim var mı?", ff.MatchedAt),
				"POST request ile veri değiştirme/oluşturma dene",
				"Farklı role'de kullanıcı ile erişim dene",
			},
			Question: "Bu admin/debug endpoint herkese açık mı? Yetkilendirme olmadan hassas veri veya fonksiyonlara erişim mümkün mü?",
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
			Question:    fmt.Sprintf("%s gerçekten erişilebilir mi? Hassas veri sızıyor mu? Exploitable mi?", ff.Name),
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
				"Evil origin ile cookie/token okunabiliyor mu?",
				"State-changing endpoint'lerde (POST/PUT/DELETE) de CORS reflection var mı?",
				"Credentials ile birlikte kullanılabilir mi?",
			},
			Question: "CORS misconfiguration exploitable mi? Sensitive data veya session token çalınabilir mi?",
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
				fmt.Sprintf("Header doğrula: curl -I %s", f.URL),
				"Tüm endpoint'lerde aynı durum mu?",
				"Exploitable impact var mı?",
			},
			Question: fmt.Sprintf("%s exploit edilebilir mi? Gerçek bir güvenlik etkisi var mı?", f.RuleName),
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
				"URL'deki parametreye ' (tek tırnak) ekle — SQL error değişiyor mu?",
				"' OR 1=1-- dene — farklı sonuç dönüyor mu?",
				"' UNION SELECT NULL-- dene — column sayısını belirle",
				"sqlmap ile otomatik test yap",
			},
		},
		"error-stack-trace": {
			vulnHint: "Information Disclosure via Stack Trace",
			verifySteps: []string{
				"Stack trace'te framework version, internal path veya credential var mı?",
				"Farklı input'larla daha fazla trace tetiklenebilir mi?",
				"Error handling düzgün yapılmamış — diğer endpoint'lerde de test et",
			},
		},
		"internal-ip": {
			vulnHint: "Internal Network Mapping",
			verifySteps: []string{
				"Internal IP başka response'larda da geçiyor mu?",
				"Bu IP'ye direkt erişim mümkün mü (SSRF üzerinden)?",
				"Network topolojisi çıkarılabilir mi?",
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
			Description: fmt.Sprintf("%s tespit edildi. Bu durum %s zafiyetine işaret edebilir.", f.RuleName, rule.vulnHint),
			FoundAt:     llm.InvestigationSource{Source: f.Source, URL: f.URL, Host: host, File: f.File},
			Evidence:    []string{truncateStr(f.Value, 200)},
			Context:     llm.InvestigationContext{},
			VerifySteps: rule.verifySteps,
			Question:    fmt.Sprintf("%s gerçek bir zafiyet göstergesi mi? Aktif olarak exploit edilebilir mi?", rule.vulnHint),
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
					Description: fmt.Sprintf("CNAME %s servisi (%s) işaret ediyor. Status: %d. Servis claim edilebilir mi?", service, cname, h.StatusCode),
					FoundAt:     llm.InvestigationSource{Source: "httpx", Host: h.Host},
					Evidence:    []string{fmt.Sprintf("CNAME: %s", cname), fmt.Sprintf("Status: %d", h.StatusCode)},
					Context:     llm.InvestigationContext{},
					VerifySteps: []string{
						fmt.Sprintf("dig %s CNAME — CNAME hala aktif mi?", h.Host),
						fmt.Sprintf("curl -I https://%s — response ne dönüyor?", h.Host),
						fmt.Sprintf("%s'de '%s' hesabını claim etmeyi dene", service, h.Host),
					},
					Question: fmt.Sprintf("%s üzerindeki CNAME dangling mi? %s servisi üzerinden subdomain takeover mümkün mü?", h.Host, service),
				})
				break // one match per CNAME is enough
			}
		}
	}
	return investigations
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
			"AWS CLI ile key doğrula: aws sts get-caller-identity --access-key-id [KEY]",
			"Aynı dosyada AWS secret key de var mı?",
			"S3 bucket erişimi dene: aws s3 ls --profile test",
		}
	case strings.Contains(f.RuleID, "github"):
		return []string{
			"Token scope kontrolü: curl -H 'Authorization: token [TOKEN]' https://api.github.com/user",
			"Hangi repo'lara erişim var?",
			"Token'ın org-level yetkileri var mı?",
		}
	case f.RuleID == "jwt-token":
		return []string{
			"JWT'yi jwt.io'da decode et — payload'da ne var?",
			"Signature verification bypass dene (alg: none)",
			"Token expired mı? Expire olmamış token ile erişim dene",
		}
	case f.RuleID == "private-key":
		return []string{
			"Key tipi ve boyutu kontrol et",
			"Bu key hangi serviste kullanılıyor?",
			"Key ile SSH veya TLS bağlantısı dene",
		}
	case strings.Contains(f.RuleID, "stripe"):
		return []string{
			"Stripe API ile key doğrula: curl https://api.stripe.com/v1/charges -u [KEY]:",
			"Live key mi yoksa test key mi?",
			"Ödeme bilgilerine erişim var mı?",
		}
	default:
		return []string{
			"Key/token'ın aktif olup olmadığını doğrula",
			"Aynı kaynakta başka credential var mı?",
			"Token scope ve yetkileri kontrol et",
		}
	}
}

func buildTechVulnVerifySteps(ff smartFuzzFinding) []string {
	tid := strings.ToLower(ff.TemplateID)
	switch {
	case strings.Contains(tid, "actuator-env"):
		return []string{
			"Response'ta plaintext password veya API key var mı?",
			"/actuator/heapdump indirilebilir mi?",
			"POST /actuator/env ile property set edilebilir mi? (RCE chain)",
		}
	case strings.Contains(tid, "heapdump"):
		return []string{
			"Heapdump'ı indir ve credential ara: strings heapdump | grep -i password",
			"JVisualVM veya Eclipse MAT ile analiz et",
			"Database connection string, API key ara",
		}
	case strings.Contains(tid, "pprof"):
		return []string{
			"Heap dump'ta credential/secret ara",
			"Goroutine dump'ta internal API path'leri ara",
			"/debug/pprof/cmdline ile başlatma argümanlarını kontrol et",
		}
	case strings.Contains(tid, "graphql"):
		return []string{
			"Introspection ile tüm type ve query'leri listele",
			"Mutation'lar var mı? Yetkilendirme kontrol et",
			"Sensitive field'lar (password, token, secret) ara",
		}
	case strings.Contains(tid, "git"):
		return []string{
			"git-dumper ile .git/ dizinini komple indir",
			"Source code'da hardcoded credential ara",
			"Commit history'de silinen secret'ları ara: git log -p | grep -i password",
		}
	case strings.Contains(tid, "env"):
		return []string{
			".env dosyasındaki credential'ları doğrula",
			"Database connection string ile bağlantı dene",
			"API key'lerin scope ve yetkilerini kontrol et",
		}
	default:
		return []string{
			fmt.Sprintf("Endpoint'e erişim doğrula: curl %s", ff.MatchedAt),
			"Hassas veri sızıyor mu kontrol et",
			"Exploit edilebilir mi değerlendir",
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
