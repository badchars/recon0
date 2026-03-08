package provider

import (
	"bufio"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/badchars/recon0/internal/config"
)

type SmartFuzz struct{}

func (s *SmartFuzz) Name() string       { return "smartfuzz" }
func (s *SmartFuzz) Stage() string      { return "vuln" }
func (s *SmartFuzz) OutputType() string { return "findings" }
func (s *SmartFuzz) Check() error       { return nil }

// smartFuzzFinding matches nuclei JSON output format for merge compatibility.
type smartFuzzFinding struct {
	TemplateID  string `json:"template-id"`
	Name        string `json:"name"`
	Severity    string `json:"severity"`
	Host        string `json:"host"`
	MatchedAt   string `json:"matched-at"`
	Type        string `json:"type"`
	Description string `json:"description,omitempty"`
	Evidence    string `json:"evidence,omitempty"`
	Source      string `json:"source,omitempty"` // known-path, prefix-expansion, tech-discovery, discovery-fuzz, cors
}

// fuzzTarget holds parsed httpx data for a single host.
type fuzzTarget struct {
	URL    string
	Host   string
	Tech   []string
	Server string
	CDN    string
}

type targetClass int

const (
	targetDirect targetClass = iota
	targetCDN
)

func (s *SmartFuzz) Run(ctx context.Context, opts *RunOpts) (*Result, error) {
	extra := opts.Config

	timeout := config.GetDuration(extra, "timeout", 10*time.Second)
	maxConcurrent := config.GetInt(extra, "max_concurrent", 30)
	skipCORS := config.GetBool(extra, "skip_cors", false)
	cdnMode := config.GetString(extra, "cdn_mode", "critical_only")
	prefixExpansion := config.GetBool(extra, "prefix_expansion", true)
	discoveryFuzz := config.GetBool(extra, "discovery_fuzz", true)
	maxProbesPerHost := config.GetInt(extra, "max_probes_per_host", 100)

	if maxConcurrent <= 0 {
		maxConcurrent = 30
	}

	// Parse httpx JSON for tech fingerprints + CDN info
	httpxPath := filepath.Join(opts.WorkDir, "raw", "httpx.hosts.txt.json")
	targets := parseFuzzTargets(httpxPath)
	if len(targets) == 0 {
		return &Result{Count: 0, OutputFile: opts.Output}, nil
	}

	// Enrich tech from HAR headers/cookies
	harDir := filepath.Join(opts.WorkDir, "har")
	enrichFuzzTechFromHAR(harDir, targets)

	// Load probe sets
	allSets := AllFuzzProbeSets()

	// Prepare output file
	os.MkdirAll(filepath.Dir(opts.Output), 0755)
	outFile, err := os.Create(opts.Output)
	if err != nil {
		return nil, fmt.Errorf("smartfuzz: create output: %w", err)
	}
	defer outFile.Close()

	var (
		mu        sync.Mutex
		writer    = bufio.NewWriter(outFile)
		total     int
		probeSent int
	)

	emit := func(f smartFuzzFinding) {
		mu.Lock()
		data, _ := json.Marshal(f)
		fmt.Fprintln(writer, string(data))
		total++
		mu.Unlock()
	}

	// HTTP client: no redirects, skip TLS verify
	client := &http.Client{
		Timeout: timeout,
		Transport: &http.Transport{
			TLSClientConfig:     &tls.Config{InsecureSkipVerify: true},
			MaxIdleConnsPerHost: 10,
			MaxIdleConns:        100,
		},
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Worker pool
	sem := make(chan struct{}, maxConcurrent)
	var wg sync.WaitGroup

	// Track runtime-discovered tech per host
	var discoveredTechMu sync.Mutex
	discoveredTech := make(map[string][]string) // URL → []tech

	// ── Phase 1: Universal probes + Tech-specific probes ──

	for _, target := range targets {
		if ctx.Err() != nil {
			break
		}

		class := classifyTarget(target)
		probes := selectFuzzProbes(allSets, target, class, cdnMode, prefixExpansion)

		if maxProbesPerHost > 0 && len(probes) > maxProbesPerHost {
			probes = probes[:maxProbesPerHost]
		}

		for _, probe := range probes {
			if ctx.Err() != nil {
				break
			}

			wg.Add(1)
			sem <- struct{}{}

			go func(t fuzzTarget, p FuzzProbe) {
				defer wg.Done()
				defer func() { <-sem }()

				mu.Lock()
				probeSent++
				mu.Unlock()

				finding := executeFuzzProbe(ctx, client, t, p)
				if finding != nil {
					emit(*finding)

					// Runtime tech discovery
					if p.TechDiscover != "" {
						discoveredTechMu.Lock()
						discoveredTech[t.URL] = append(discoveredTech[t.URL], p.TechDiscover)
						discoveredTechMu.Unlock()
					}
				}
			}(target, probe)
		}

		// CORS probe
		if !skipCORS {
			wg.Add(1)
			sem <- struct{}{}

			go func(t fuzzTarget) {
				defer wg.Done()
				defer func() { <-sem }()

				mu.Lock()
				probeSent++
				mu.Unlock()

				finding := fuzzProbeCORS(ctx, client, t)
				if finding != nil {
					emit(*finding)
				}
			}(target)
		}
	}

	wg.Wait()

	// ── Phase 2: Runtime tech discovery — run expanded probes for newly discovered tech ──

	if len(discoveredTech) > 0 {
		for _, target := range targets {
			if ctx.Err() != nil {
				break
			}

			techs, ok := discoveredTech[target.URL]
			if !ok {
				continue
			}

			// Create a virtual target with discovered tech added
			enrichedTarget := target
			for _, tech := range techs {
				enrichedTarget.Tech = appendTechIfNew(enrichedTarget.Tech, tech)
			}

			// Get tech-specific probes that weren't already sent
			probes := selectTechDiscoveryProbes(allSets, enrichedTarget, target.Tech, prefixExpansion)
			if len(probes) == 0 {
				continue
			}

			for _, probe := range probes {
				if ctx.Err() != nil {
					break
				}

				wg.Add(1)
				sem <- struct{}{}

				go func(t fuzzTarget, p FuzzProbe) {
					defer wg.Done()
					defer func() { <-sem }()

					mu.Lock()
					probeSent++
					mu.Unlock()

					finding := executeFuzzProbe(ctx, client, t, p)
					if finding != nil {
						finding.Source = "tech-discovery"
						emit(*finding)
					}
				}(target, probe)
			}
		}

		wg.Wait()
	}

	// ── Phase 3: Discovery-based fuzzing ──

	if discoveryFuzz {
		discTargets := generateDiscoveryFuzzTargets(opts.WorkDir)

		for _, dt := range discTargets {
			if ctx.Err() != nil {
				break
			}

			wg.Add(1)
			sem <- struct{}{}

			go func(d discoverFuzzTarget) {
				defer wg.Done()
				defer func() { <-sem }()

				mu.Lock()
				probeSent++
				mu.Unlock()

				finding := executeDiscoveryProbe(ctx, client, d)
				if finding != nil {
					emit(*finding)
				}
			}(dt)
		}

		wg.Wait()
	}

	mu.Lock()
	writer.Flush()
	mu.Unlock()

	return &Result{
		Count:      total,
		OutputFile: opts.Output,
		Extra: map[string]any{
			"hosts_probed":   len(targets),
			"probes_sent":    probeSent,
			"findings":       total,
			"tech_discovered": len(discoveredTech),
		},
	}, nil
}

// ── Target Parsing ──

func parseFuzzTargets(path string) []fuzzTarget {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()

	seen := make(map[string]bool)
	var targets []fuzzTarget

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		var entry struct {
			URL     string   `json:"url"`
			Host    string   `json:"host"`
			Tech    []string `json:"tech"`
			Server  string   `json:"server"`
			CDNName string   `json:"cdn_name"`
		}
		if json.Unmarshal(scanner.Bytes(), &entry) != nil || entry.URL == "" {
			continue
		}

		if seen[entry.URL] {
			continue
		}
		seen[entry.URL] = true

		targets = append(targets, fuzzTarget{
			URL:    entry.URL,
			Host:   entry.Host,
			Tech:   entry.Tech,
			Server: entry.Server,
			CDN:    entry.CDNName,
		})
	}

	return targets
}

func classifyTarget(t fuzzTarget) targetClass {
	if t.CDN != "" {
		return targetCDN
	}
	return targetDirect
}

// ── Probe Selection ──

func selectFuzzProbes(allSets []FuzzProbeSet, target fuzzTarget, class targetClass, cdnMode string, prefixExpansion bool) []FuzzProbe {
	var probes []FuzzProbe

	for _, set := range allSets {
		for _, probe := range set.Probes {
			// Universal probes: always sent
			if probe.Universal {
				// CDN mode: skip non-critical universal probes for CDN hosts
				if class == targetCDN && cdnMode == "skip" {
					continue
				}
				probes = append(probes, probe)
				probes[len(probes)-1].RuleID = probe.RuleID // preserve original
				continue
			}

			// Non-universal: need tech match
			if set.TechMatch == nil {
				continue
			}

			if !matchesFuzzTech(target, set.TechMatch) {
				continue
			}

			// CDN hosts: skip tech-specific probes unless cdn_mode=full
			if class == targetCDN && cdnMode != "full" {
				continue
			}

			if prefixExpansion {
				expanded := ExpandWithPrefixes(probe)
				for i := range expanded {
					expanded[i].RuleID = probe.RuleID
					if i > 0 {
						expanded[i].RuleID = probe.RuleID + "-prefix"
					}
				}
				probes = append(probes, expanded...)
			} else {
				probes = append(probes, probe)
			}
		}
	}

	return probes
}

// selectTechDiscoveryProbes returns probes for newly discovered tech that weren't already sent.
func selectTechDiscoveryProbes(allSets []FuzzProbeSet, enrichedTarget fuzzTarget, originalTech []string, prefixExpansion bool) []FuzzProbe {
	var probes []FuzzProbe

	for _, set := range allSets {
		if set.TechMatch == nil {
			continue
		}

		// Already matched with original tech? Skip — these were already sent.
		alreadyMatched := false
		for _, pattern := range set.TechMatch {
			lower := strings.ToLower(pattern)
			for _, tech := range originalTech {
				if strings.Contains(strings.ToLower(tech), lower) {
					alreadyMatched = true
					break
				}
			}
			if alreadyMatched {
				break
			}
		}
		if alreadyMatched {
			continue
		}

		// New tech — check if enriched target matches
		if !matchesFuzzTech(enrichedTarget, set.TechMatch) {
			continue
		}

		for _, probe := range set.Probes {
			if probe.Universal {
				continue // universal already sent
			}

			if prefixExpansion {
				probes = append(probes, ExpandWithPrefixes(probe)...)
			} else {
				probes = append(probes, probe)
			}
		}
	}

	return probes
}

func matchesFuzzTech(target fuzzTarget, patterns []string) bool {
	for _, pattern := range patterns {
		lower := strings.ToLower(pattern)

		for _, tech := range target.Tech {
			if strings.Contains(strings.ToLower(tech), lower) {
				return true
			}
		}

		if target.Server != "" && strings.Contains(strings.ToLower(target.Server), lower) {
			return true
		}
	}
	return false
}

func appendTechIfNew(techs []string, newTech string) []string {
	for _, t := range techs {
		if strings.EqualFold(t, newTech) {
			return techs
		}
	}
	return append(techs, newTech)
}

// ── Probe Execution ──

func executeFuzzProbe(ctx context.Context, client *http.Client, target fuzzTarget, probe FuzzProbe) *smartFuzzFinding {
	probeURL := strings.TrimRight(target.URL, "/") + probe.Path

	method := probe.Method
	if method == "" {
		method = "GET"
	}

	var bodyReader io.Reader
	if probe.Body != "" {
		bodyReader = strings.NewReader(probe.Body)
	}

	req, err := http.NewRequestWithContext(ctx, method, probeURL, bodyReader)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; recon0-probe/1.0)")
	for k, v := range probe.Headers {
		req.Header.Set(k, v)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil
	}

	// Status code check
	statusMatch := false
	if len(probe.ExpectStatus) == 0 {
		statusMatch = resp.StatusCode == 200
	} else {
		for _, s := range probe.ExpectStatus {
			if resp.StatusCode == s {
				statusMatch = true
				break
			}
		}
	}
	if !statusMatch {
		return nil
	}

	bodyStr := string(body)

	// Special case: heapdump/pprof heap — check for large binary response
	if probe.RuleID == "spring-actuator-heapdump" || probe.RuleID == "go-pprof-heap" {
		if resp.ContentLength > 1024*1024 || len(body) > 1024*100 {
			return &smartFuzzFinding{
				TemplateID:  probe.RuleID,
				Name:        probe.RuleName,
				Severity:    probe.Severity,
				Host:        target.URL,
				MatchedAt:   probeURL,
				Type:        "http",
				Description: probe.Description,
				Evidence:    fmt.Sprintf("Content-Length: %d bytes", resp.ContentLength),
				Source:      "known-path",
			}
		}
		return nil
	}

	// Special case: pprof cmdline
	if probe.RuleID == "go-pprof-cmdline" {
		if len(body) > 0 && !strings.Contains(bodyStr, "<html") && !strings.Contains(bodyStr, "<HTML") {
			evidence := bodyStr
			if len(evidence) > 500 {
				evidence = evidence[:500]
			}
			return &smartFuzzFinding{
				TemplateID:  probe.RuleID,
				Name:        probe.RuleName,
				Severity:    probe.Severity,
				Host:        target.URL,
				MatchedAt:   probeURL,
				Type:        "http",
				Description: probe.Description,
				Evidence:    evidence,
				Source:      "known-path",
			}
		}
		return nil
	}

	// Reject body filter
	for _, reject := range probe.RejectBody {
		if strings.Contains(bodyStr, reject) {
			return nil
		}
	}

	// Generic 404 page filter
	if fuzzIsGeneric404(bodyStr) && !fuzzContainsExpected(bodyStr, probe.ExpectBody) {
		return nil
	}

	// Expect body match
	if len(probe.ExpectBody) > 0 {
		if !fuzzContainsExpected(bodyStr, probe.ExpectBody) {
			return nil
		}
	} else if len(body) == 0 {
		return nil
	}

	evidence := bodyStr
	if len(evidence) > 500 {
		evidence = evidence[:500]
	}

	source := "known-path"
	if strings.HasSuffix(probe.RuleID, "-prefix") {
		source = "prefix-expansion"
	}

	return &smartFuzzFinding{
		TemplateID:  probe.RuleID,
		Name:        probe.RuleName,
		Severity:    probe.Severity,
		Host:        target.URL,
		MatchedAt:   probeURL,
		Type:        "http",
		Description: probe.Description,
		Evidence:    evidence,
		Source:      source,
	}
}

// executeDiscoveryProbe sends a discovery-based fuzz request and evaluates the response.
func executeDiscoveryProbe(ctx context.Context, client *http.Client, dt discoverFuzzTarget) *smartFuzzFinding {
	probeURL := strings.TrimRight(dt.BaseURL, "/") + dt.Path

	req, err := http.NewRequestWithContext(ctx, dt.Method, probeURL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; recon0-probe/1.0)")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1024*1024))
	if err != nil {
		return nil
	}

	// Only interested in 200 responses for discovery
	if resp.StatusCode != 200 {
		return nil
	}

	bodyStr := string(body)

	// Reject generic 404 pages that return 200
	if fuzzIsGeneric404(bodyStr) {
		return nil
	}

	// Reject empty or tiny responses
	if len(body) < 50 {
		return nil
	}

	// Reject obvious HTML error pages
	lower := strings.ToLower(bodyStr)
	if strings.Contains(lower, "page not found") || strings.Contains(lower, "access denied") || strings.Contains(lower, "403 forbidden") {
		return nil
	}

	evidence := fmt.Sprintf("%d %s, %d bytes", resp.StatusCode, http.StatusText(resp.StatusCode), len(body))

	return &smartFuzzFinding{
		TemplateID:  dt.RuleID,
		Name:        dt.RuleName,
		Severity:    "info",
		Host:        dt.BaseURL,
		MatchedAt:   probeURL,
		Type:        "http",
		Description: fmt.Sprintf("Discovered via %s fuzzing", dt.Source),
		Evidence:    evidence,
		Source:      "discovery-fuzz",
	}
}

// ── CORS Probing ──

func fuzzProbeCORS(ctx context.Context, client *http.Client, target fuzzTarget) *smartFuzzFinding {
	req, err := http.NewRequestWithContext(ctx, "GET", target.URL, nil)
	if err != nil {
		return nil
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; recon0-probe/1.0)")
	req.Header.Set("Origin", "https://evil.recon0.test")

	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	io.Copy(io.Discard, resp.Body)

	acao := resp.Header.Get("Access-Control-Allow-Origin")
	acac := resp.Header.Get("Access-Control-Allow-Credentials")

	if acao == "" {
		return nil
	}

	if acao == "https://evil.recon0.test" {
		severity := "medium"
		desc := "CORS allows arbitrary origin reflection"
		if strings.EqualFold(acac, "true") {
			severity = "high"
			desc = "CORS allows arbitrary origin reflection WITH credentials — cookie theft possible"
		}
		return &smartFuzzFinding{
			TemplateID:  "cors-origin-reflection",
			Name:        "CORS Origin Reflection",
			Severity:    severity,
			Host:        target.URL,
			MatchedAt:   target.URL,
			Type:        "http",
			Description: desc,
			Evidence:    fmt.Sprintf("Access-Control-Allow-Origin: %s, Access-Control-Allow-Credentials: %s", acao, acac),
			Source:      "cors",
		}
	}

	if acao == "*" && strings.EqualFold(acac, "true") {
		return &smartFuzzFinding{
			TemplateID:  "cors-wildcard-credentials",
			Name:        "CORS Wildcard with Credentials",
			Severity:    "medium",
			Host:        target.URL,
			MatchedAt:   target.URL,
			Type:        "http",
			Description: "CORS allows wildcard origin with credentials header",
			Evidence:    fmt.Sprintf("Access-Control-Allow-Origin: *, Access-Control-Allow-Credentials: %s", acac),
			Source:      "cors",
		}
	}

	return nil
}

// ── HAR Tech Enrichment (reused from activeprobe pattern) ──

func enrichFuzzTechFromHAR(harDir string, targets []fuzzTarget) {
	hostIdx := make(map[string]int, len(targets))
	for i, t := range targets {
		hostIdx[t.Host] = i
	}

	harFiles, _ := filepath.Glob(filepath.Join(harDir, "*.har"))
	for _, harFile := range harFiles {
		enrichFuzzFromSingleHAR(harFile, targets, hostIdx)
	}
}

func enrichFuzzFromSingleHAR(harFile string, targets []fuzzTarget, hostIdx map[string]int) {
	f, err := os.Open(harFile)
	if err != nil {
		return
	}
	defer f.Close()

	var har struct {
		Log struct {
			Entries []struct {
				Request struct {
					URL string `json:"url"`
				} `json:"request"`
				Response struct {
					Headers []struct {
						Name  string `json:"name"`
						Value string `json:"value"`
					} `json:"headers"`
					Cookies []struct {
						Name string `json:"name"`
					} `json:"cookies"`
				} `json:"response"`
			} `json:"entries"`
		} `json:"log"`
	}

	data, err := io.ReadAll(io.LimitReader(f, 50*1024*1024))
	if err != nil {
		return
	}
	if json.Unmarshal(data, &har) != nil {
		return
	}

	for _, entry := range har.Log.Entries {
		host := fuzzExtractHost(entry.Request.URL)
		if host == "" {
			continue
		}

		idx, ok := hostIdx[host]
		if !ok {
			continue
		}

		for _, h := range entry.Response.Headers {
			hLower := strings.ToLower(h.Name)
			vLower := strings.ToLower(h.Value)

			for _, rule := range headerTechRules {
				if hLower != rule.Header {
					continue
				}
				if rule.Contains == "" || strings.Contains(vLower, rule.Contains) {
					fuzzAddTech(&targets[idx], rule.Tech)
				}
			}
		}

		for _, c := range entry.Response.Cookies {
			cLower := strings.ToLower(c.Name)
			for _, rule := range cookieTechRules {
				if cLower == strings.ToLower(rule.Cookie) {
					fuzzAddTech(&targets[idx], rule.Tech)
				}
			}
		}
	}
}

func fuzzExtractHost(rawURL string) string {
	if idx := strings.Index(rawURL, "://"); idx >= 0 {
		rest := rawURL[idx+3:]
		if slash := strings.Index(rest, "/"); slash >= 0 {
			rest = rest[:slash]
		}
		if colon := strings.LastIndex(rest, ":"); colon >= 0 {
			rest = rest[:colon]
		}
		return rest
	}
	return ""
}

func fuzzAddTech(target *fuzzTarget, tech string) {
	for _, t := range target.Tech {
		if strings.EqualFold(t, tech) {
			return
		}
	}
	target.Tech = append(target.Tech, tech)
}

// ── HAR-based Tech Detection Rules ──

type headerTechRule struct {
	Header   string
	Contains string
	Tech     string
}

type cookieTechRule struct {
	Cookie string
	Tech   string
}

var headerTechRules = []headerTechRule{
	{"server", "go-http-server", "Go"},
	{"server", "gunicorn", "Python"},
	{"server", "uvicorn", "Python"},
	{"server", "daphne", "Django"},
	{"server", "werkzeug", "Flask"},
	{"server", "webrick", "Ruby"},
	{"server", "puma", "Ruby"},
	{"server", "unicorn", "Ruby"},
	{"server", "passenger", "Ruby"},
	{"server", "thin", "Ruby"},
	{"server", "kestrel", ".NET"},
	{"server", "microsoft-iis", "IIS"},
	{"server", "microsoft-httpapi", ".NET"},
	{"server", "apache-coyote", "Java"},
	{"server", "tomcat", "Java"},
	{"server", "jetty", "Java"},
	{"server", "wildfly", "Java"},
	{"server", "glassfish", "Java"},
	{"server", "openresty", "Nginx"},
	{"server", "envoy", "Envoy"},
	{"server", "istio-envoy", "Envoy"},
	{"server", "caddy", "Caddy"},
	{"server", "tornado", "Python"},
	{"x-powered-by", "express", "Express"},
	{"x-powered-by", "php", "PHP"},
	{"x-powered-by", "asp.net", "ASP.NET"},
	{"x-powered-by", "servlet", "Java"},
	{"x-powered-by", "jsp", "Java"},
	{"x-powered-by", "next.js", "Next.js"},
	{"x-powered-by", "nuxt", "Nuxt"},
	{"x-powered-by", "django", "Django"},
	{"x-powered-by", "flask", "Flask"},
	{"x-powered-by", "rails", "Ruby"},
	{"x-powered-by", "phusion passenger", "Ruby"},
	{"x-runtime", "", "Ruby"},
	{"x-aspnet-version", "", "ASP.NET"},
	{"x-aspnetmvc-version", "", "ASP.NET"},
	{"x-generator", "drupal", "Drupal"},
	{"x-generator", "wordpress", "WordPress"},
	{"x-generator", "joomla", "Joomla"},
	{"x-turbo-charged-by", "litespeed", "LiteSpeed"},
	{"x-debug-token", "", "Symfony"},
}

var cookieTechRules = []cookieTechRule{
	{"JSESSIONID", "Java"},
	{"PHPSESSID", "PHP"},
	{"laravel_session", "Laravel"},
	{"ASP.NET_SessionId", "ASP.NET"},
	{"ASPXAUTH", "ASP.NET"},
	{"connect.sid", "Express"},
	{"_csrf", "Ruby"},
	{"rack.session", "Ruby"},
	{"ci_session", "PHP"},
	{"PLAY_SESSION", "Java"},
	{"csrftoken", "Django"},
	{"sessionid", "Django"},
	{"__cfduid", "Cloudflare"},
}

// ── Helpers ──

func fuzzContainsExpected(body string, patterns []string) bool {
	for _, p := range patterns {
		if strings.Contains(body, p) {
			return true
		}
	}
	return false
}

func fuzzIsGeneric404(body string) bool {
	lower := strings.ToLower(body)
	return strings.Contains(lower, "<title>404") ||
		strings.Contains(lower, "page not found") ||
		strings.Contains(lower, "not found</") ||
		strings.Contains(lower, "404 not found")
}

func init() { Register(&SmartFuzz{}) }
