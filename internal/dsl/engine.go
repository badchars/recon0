package dsl

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
)

// Engine runs rules against various content sources.
type Engine struct {
	rules      []Rule
	findings   []Finding
	mu         sync.Mutex
	jsManifest map[string]string // filename → original URL

	// Compiled false-positive patterns (lazily built)
	fpCache map[string][]*regexp.Regexp
}

// NewEngine creates a new DSL engine with compiled rules.
func NewEngine(rules []Rule) *Engine {
	return &Engine{
		rules:   rules,
		fpCache: make(map[string][]*regexp.Regexp),
	}
}

// SetJSManifest sets the JS filename→URL mapping for enriching JS findings.
func (e *Engine) SetJSManifest(m map[string]string) {
	e.jsManifest = m
}

// ScanHAR scans a HAR file's request URLs and response bodies.
func (e *Engine) ScanHAR(harPath string) error {
	data, err := os.ReadFile(harPath)
	if err != nil {
		return err
	}

	var har struct {
		Log struct {
			Entries []struct {
				Request struct {
					URL string `json:"url"`
				} `json:"request"`
				Response struct {
					Content struct {
						MimeType string `json:"mimeType"`
						Text     string `json:"text"`
					} `json:"content"`
				} `json:"response"`
			} `json:"entries"`
		} `json:"log"`
	}
	if err := json.Unmarshal(data, &har); err != nil {
		return err
	}

	basename := filepath.Base(harPath)

	for _, entry := range har.Log.Entries {
		// Scan request URL
		e.matchRules(entry.Request.URL, SourceHAR, basename, entry.Request.URL)

		// Scan response body (skip binary)
		ct := entry.Response.Content.MimeType
		if entry.Response.Content.Text != "" && isTextMime(ct) {
			e.matchRules(entry.Response.Content.Text, SourceHAR, basename, entry.Request.URL)
		}
	}

	return nil
}

// ScanHARHeaders scans a HAR file's response headers.
func (e *Engine) ScanHARHeaders(harPath string) error {
	data, err := os.ReadFile(harPath)
	if err != nil {
		return err
	}

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
				} `json:"response"`
			} `json:"entries"`
		} `json:"log"`
	}
	if err := json.Unmarshal(data, &har); err != nil {
		return err
	}

	basename := filepath.Base(harPath)

	for _, entry := range har.Log.Entries {
		// Build header string for scanning
		var headerStr strings.Builder
		for _, h := range entry.Response.Headers {
			fmt.Fprintf(&headerStr, "%s: %s\n", h.Name, h.Value)
		}

		// Check for "missing" header rules (inverted match)
		headerContent := headerStr.String()
		for _, rule := range e.rules {
			if !hasSource(rule.Sources, SourceHARHeaders) {
				continue
			}

			// Special handling for "missing-*" rules: finding means header is ABSENT
			if strings.HasPrefix(rule.ID, "missing-") {
				if !rule.Compiled.MatchString(headerContent) {
					e.addFinding(Finding{
						RuleID:   rule.ID,
						RuleName: rule.Name,
						Severity: rule.Severity,
						Value:    "header not found",
						Source:   string(SourceHARHeaders),
						File:     basename,
						URL:      entry.Request.URL,
					})
				}
				continue
			}

			// Normal header scanning
			matches := rule.Compiled.FindAllString(headerContent, 5)
			for _, m := range matches {
				if e.isFalsePositive(rule, m) {
					continue
				}
				e.addFinding(Finding{
					RuleID:   rule.ID,
					RuleName: rule.Name,
					Severity: rule.Severity,
					Value:    truncateValue(m, 200),
					Source:   string(SourceHARHeaders),
					File:     basename,
					URL:      entry.Request.URL,
				})
			}
		}
	}

	return nil
}

// ScanJSFile scans a JavaScript file for secrets and patterns.
func (e *Engine) ScanJSFile(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()

	// Check file size
	info, err := f.Stat()
	if err != nil {
		return err
	}
	if info.Size() > 10*1024*1024 {
		return nil // skip large files
	}

	basename := filepath.Base(path)

	// Resolve original URL from manifest
	jsURL := ""
	if e.jsManifest != nil {
		jsURL = e.jsManifest[basename]
	}

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	lineNum := 0
	for scanner.Scan() {
		lineNum++
		line := scanner.Text()

		for _, rule := range e.rules {
			if !hasSource(rule.Sources, SourceJS) {
				continue
			}

			matches := rule.Compiled.FindAllString(line, 3)
			for _, m := range matches {
				if e.isFalsePositive(rule, m) {
					continue
				}
				e.addFinding(Finding{
					RuleID:   rule.ID,
					RuleName: rule.Name,
					Severity: rule.Severity,
					Value:    truncateValue(m, 200),
					Source:   string(SourceJS),
					File:     basename,
					URL:      jsURL,
					Line:     lineNum,
				})
			}
		}
	}

	return scanner.Err()
}

// ScanEndpoints scans a list of endpoint URLs for interesting patterns.
func (e *Engine) ScanEndpoints(endpointsFile string) error {
	f, err := os.Open(endpointsFile)
	if err != nil {
		return err
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}

		// Parse JSON line to get URL
		var ep struct {
			URL string `json:"url"`
		}
		if err := json.Unmarshal([]byte(line), &ep); err != nil {
			continue
		}

		for _, rule := range e.rules {
			if !hasSource(rule.Sources, SourceEndpoints) {
				continue
			}

			if rule.Compiled.MatchString(ep.URL) {
				if e.isFalsePositive(rule, ep.URL) {
					continue
				}
				e.addFinding(Finding{
					RuleID:   rule.ID,
					RuleName: rule.Name,
					Severity: rule.Severity,
					Value:    truncateValue(ep.URL, 200),
					Source:   string(SourceEndpoints),
					File:     "endpoints.json",
					URL:      ep.URL,
				})
			}
		}
	}

	return scanner.Err()
}

// Findings returns all collected findings.
func (e *Engine) Findings() []Finding {
	e.mu.Lock()
	defer e.mu.Unlock()
	result := make([]Finding, len(e.findings))
	copy(result, e.findings)
	return result
}

// DeduplicatedFindings returns findings deduplicated by (rule_id, value).
func (e *Engine) DeduplicatedFindings() []Finding {
	e.mu.Lock()
	defer e.mu.Unlock()

	seen := make(map[string]bool)
	var result []Finding

	for _, f := range e.findings {
		key := f.RuleID + "|" + f.Value
		if !seen[key] {
			seen[key] = true
			result = append(result, f)
		}
	}

	return result
}

// matchRules runs all rules of a given source type against content.
func (e *Engine) matchRules(content string, source RuleSource, file, reqURL string) {
	for _, rule := range e.rules {
		if !hasSource(rule.Sources, source) {
			continue
		}

		matches := rule.Compiled.FindAllString(content, 5)
		for _, m := range matches {
			if e.isFalsePositive(rule, m) {
				continue
			}
			e.addFinding(Finding{
				RuleID:   rule.ID,
				RuleName: rule.Name,
				Severity: rule.Severity,
				Value:    truncateValue(m, 200),
				Source:   string(source),
				File:     file,
				URL:      reqURL,
			})
		}
	}
}

func (e *Engine) addFinding(f Finding) {
	e.mu.Lock()
	defer e.mu.Unlock()
	e.findings = append(e.findings, f)
}

func (e *Engine) isFalsePositive(rule Rule, value string) bool {
	if len(rule.FalsePos) == 0 {
		return false
	}

	e.mu.Lock()
	patterns, cached := e.fpCache[rule.ID]
	if !cached {
		for _, fp := range rule.FalsePos {
			if re, err := regexp.Compile(fp); err == nil {
				patterns = append(patterns, re)
			}
		}
		e.fpCache[rule.ID] = patterns
	}
	e.mu.Unlock()

	for _, re := range patterns {
		if re.MatchString(value) {
			return true
		}
	}
	return false
}

func hasSource(sources []RuleSource, target RuleSource) bool {
	for _, s := range sources {
		if s == target {
			return true
		}
	}
	return false
}

func isTextMime(ct string) bool {
	ct = strings.ToLower(ct)
	return strings.Contains(ct, "text/") ||
		strings.Contains(ct, "json") ||
		strings.Contains(ct, "xml") ||
		strings.Contains(ct, "javascript") ||
		strings.Contains(ct, "html")
}

func truncateValue(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}
