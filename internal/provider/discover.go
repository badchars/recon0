package provider

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/badchars/recon0/internal/cdp"
)

// ParamDetail holds enriched parameter info extracted from HAR request data.
type ParamDetail struct {
	Name  string `json:"name"`
	Value string `json:"value,omitempty"`
	Type  string `json:"type,omitempty"` // numeric, uuid, email, url, boolean, string
}

// Endpoint represents a discovered API endpoint or URL.
type Endpoint struct {
	URL            string        `json:"url"`
	Method         string        `json:"method"`
	Source         string        `json:"source"` // "har", "js", "html", "sourcemap"
	SourceFile     string        `json:"source_file"`
	Context        string        `json:"context,omitempty"`
	Params         []string      `json:"params,omitempty"`
	ParamDetails   []ParamDetail `json:"param_details,omitempty"`
	BodyFields     []string      `json:"body_fields,omitempty"`
	ResponseFields []string      `json:"response_fields,omitempty"`
	StatusCode     int           `json:"status_code,omitempty"`
	ContentType    string        `json:"content_type,omitempty"`
	APIVersion     string        `json:"api_version,omitempty"`
	NextVersion    string        `json:"next_version,omitempty"`
}

type Discover struct{}

func (d *Discover) Name() string       { return "discover" }
func (d *Discover) Stage() string      { return "discover" }
func (d *Discover) OutputType() string { return "endpoints" }
func (d *Discover) Check() error       { return nil }

func (d *Discover) Run(ctx context.Context, opts *RunOpts) (*Result, error) {
	harDir := filepath.Join(opts.WorkDir, "har")
	jsDir := filepath.Join(opts.WorkDir, "js")

	// Read target domain for scope filtering
	targetDomain := ReadDomainFromFile(filepath.Join(opts.WorkDir, "input", "domains.txt"))

	// Output file (JSON Lines)
	os.MkdirAll(filepath.Dir(opts.Output), 0755)
	outFile, err := os.Create(opts.Output)
	if err != nil {
		return nil, fmt.Errorf("discover: create output: %w", err)
	}
	defer outFile.Close()
	outWriter := bufio.NewWriter(outFile)

	var (
		mu    sync.Mutex
		seen  = make(map[string]bool) // "METHOD url" dedup key
		total int
	)

	writeEndpoint := func(ep Endpoint) {
		// Filter: only include URLs in scope (target domain + subdomains)
		if strings.HasPrefix(ep.URL, "http") && !isInScope(ep.URL, targetDomain) {
			return
		}
		key := ep.Method + " " + ep.URL
		mu.Lock()
		defer mu.Unlock()
		if seen[key] {
			return
		}
		seen[key] = true
		data, _ := json.Marshal(ep)
		fmt.Fprintln(outWriter, string(data))
		total++
	}

	// 1. Parse HAR files for request URLs, methods, params
	harFiles, _ := filepath.Glob(filepath.Join(harDir, "*.har"))
	for _, harFile := range harFiles {
		if ctx.Err() != nil {
			break
		}
		d.extractFromHAR(harFile, writeEndpoint)
	}

	// 2. Load JS manifest (filename → original URL mapping from cdpcrawl)
	jsManifest := loadJSManifest(filepath.Join(jsDir, "_manifest.json"))

	// 3. Scan JS files for endpoints + follow import chain
	jsChain := newJSChainFollower(ctx, jsDir, writeEndpoint, jsManifest)
	jsChain.scanExistingFiles()

	outWriter.Flush()

	return &Result{
		Count:      total,
		OutputFile: opts.Output,
		Extra: map[string]any{
			"har_files_scanned": len(harFiles),
			"js_files_scanned":  jsChain.scannedCount,
			"js_downloaded":     jsChain.downloadedCount,
			"sourcemaps_parsed": jsChain.sourcemapCount,
		},
	}, nil
}

// ── JS Import Chain Follower ──

const (
	maxChainDepth   = 3
	maxJSDownloads  = 500
	maxSourceMapMB  = 50
)

// jsChainFollower recursively scans JS files, downloading referenced JS and source maps.
type jsChainFollower struct {
	ctx             context.Context
	jsDir           string
	emit            func(Endpoint)
	manifest        map[string]string // filename → original URL
	seenHash        map[string]bool   // SHA256 dedup for downloads
	scannedFiles    map[string]bool   // already scanned local files
	mu              sync.Mutex
	scannedCount    int
	downloadedCount int
	sourcemapCount  int
	client          *http.Client
}

func newJSChainFollower(ctx context.Context, jsDir string, emit func(Endpoint), manifest map[string]string) *jsChainFollower {
	return &jsChainFollower{
		ctx:          ctx,
		jsDir:        jsDir,
		emit:         emit,
		manifest:     manifest,
		seenHash:     make(map[string]bool),
		scannedFiles: make(map[string]bool),
		client:       &http.Client{Timeout: 15 * time.Second},
	}
}

// loadJSManifest reads the JS filename→URL mapping created by cdpcrawl.
func loadJSManifest(path string) map[string]string {
	data, err := os.ReadFile(path)
	if err != nil {
		return make(map[string]string)
	}
	var m map[string]string
	if err := json.Unmarshal(data, &m); err != nil {
		return make(map[string]string)
	}
	return m
}

// scanExistingFiles scans all JS files already in jsDir, then follows import chains.
func (jc *jsChainFollower) scanExistingFiles() {
	jsFiles, _ := filepath.Glob(filepath.Join(jc.jsDir, "*"))

	// Build a hash set of existing files (so we don't re-download them)
	for _, f := range jsFiles {
		data, err := os.ReadFile(f)
		if err == nil && len(data) > 0 {
			hash := fmt.Sprintf("%x", sha256.Sum256(data))
			jc.seenHash[hash] = true
		}
	}

	// Scan each file — discovered references are queued
	var queue []jsQueueItem
	for _, f := range jsFiles {
		if jc.ctx.Err() != nil {
			return
		}
		refs := jc.scanFile(f, 0)
		for _, ref := range refs {
			queue = append(queue, jsQueueItem{url: ref, depth: 1})
		}
	}

	// Process queue: download → scan → enqueue new refs
	for len(queue) > 0 {
		if jc.ctx.Err() != nil {
			return
		}
		item := queue[0]
		queue = queue[1:]

		if item.depth > maxChainDepth {
			continue
		}
		if jc.downloadedCount >= maxJSDownloads {
			break
		}

		localPath, downloaded := jc.downloadFile(item.url)
		if !downloaded || localPath == "" {
			continue
		}

		refs := jc.scanFile(localPath, item.depth)
		for _, ref := range refs {
			queue = append(queue, jsQueueItem{url: ref, depth: item.depth + 1})
		}
	}
}

type jsQueueItem struct {
	url   string
	depth int
}

// sourceURL returns the original URL for a JS filename from the manifest.
func (jc *jsChainFollower) sourceURL(basename string) string {
	if url, ok := jc.manifest[basename]; ok {
		return url
	}
	return ""
}

// scanFile scans a single JS file for endpoints and returns discovered JS/map references.
func (jc *jsChainFollower) scanFile(path string, depth int) []string {
	jc.mu.Lock()
	if jc.scannedFiles[path] {
		jc.mu.Unlock()
		return nil
	}
	jc.scannedFiles[path] = true
	jc.scannedCount++
	jc.mu.Unlock()

	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}

	// Skip files > 10MB
	if len(data) > 10*1024*1024 {
		return nil
	}

	content := string(data)
	basename := filepath.Base(path)
	isMap := strings.HasSuffix(path, ".map")

	// If it's a source map, parse sourcesContent for endpoint extraction
	if isMap {
		return jc.scanSourceMap(content, basename)
	}

	// Extract endpoints (existing logic)
	jc.extractEndpoints(content, basename)

	// Find references to other JS files and source maps
	return jc.extractJSReferences(content)
}

// extractEndpoints extracts API endpoints from JS content (existing patterns).
func (jc *jsChainFollower) extractEndpoints(content, basename string) {
	srcURL := jc.sourceURL(basename)

	// Full URLs
	for _, match := range jsURLPatterns.FindAllString(content, -1) {
		jc.emit(Endpoint{
			URL:        match,
			Method:     "GET",
			Source:     "js",
			SourceFile: srcURL,
		})
	}

	// API paths
	for _, match := range jsAPIPathPattern.FindAllString(content, -1) {
		match = strings.Trim(match, "\"'`")
		jc.emit(Endpoint{
			URL:        match,
			Method:     "GET",
			Source:     "js",
			SourceFile: srcURL,
			Context:    "api_path",
		})
	}

	// fetch() calls
	for _, m := range jsFetchPattern.FindAllStringSubmatch(content, -1) {
		if len(m) >= 2 {
			jc.emit(Endpoint{
				URL:        strings.Trim(m[1], "\"'`"),
				Method:     "GET",
				Source:     "js",
				SourceFile: srcURL,
				Context:    "fetch",
			})
		}
	}

	// axios calls
	for _, m := range jsAxiosPattern.FindAllStringSubmatch(content, -1) {
		if len(m) >= 3 {
			jc.emit(Endpoint{
				URL:        strings.Trim(m[2], "\"'`"),
				Method:     strings.ToUpper(m[1]),
				Source:     "js",
				SourceFile: srcURL,
				Context:    "axios",
			})
		}
	}
}

// extractJSReferences finds references to other JS files and source maps.
func (jc *jsChainFollower) extractJSReferences(content string) []string {
	var refs []string
	seen := make(map[string]bool)

	addRef := func(ref string) {
		ref = strings.Trim(ref, "\"'`")
		if ref == "" || seen[ref] {
			return
		}
		// Only follow full URLs (relative paths can't be resolved without base URL)
		if !strings.HasPrefix(ref, "http://") && !strings.HasPrefix(ref, "https://") {
			return
		}
		seen[ref] = true
		refs = append(refs, ref)
	}

	// ES module imports: import ... from "https://..."
	for _, m := range jsImportPattern.FindAllStringSubmatch(content, -1) {
		if len(m) >= 2 {
			addRef(m[1])
		}
	}

	// Dynamic imports: import("https://...")
	for _, m := range jsDynImportPattern.FindAllStringSubmatch(content, -1) {
		if len(m) >= 2 {
			addRef(m[1])
		}
	}

	// require(): require("https://...")
	for _, m := range jsRequirePattern.FindAllStringSubmatch(content, -1) {
		if len(m) >= 2 {
			addRef(m[1])
		}
	}

	// Source map URLs: //# sourceMappingURL=...
	for _, m := range jsSourceMapPattern.FindAllStringSubmatch(content, -1) {
		if len(m) >= 2 {
			ref := m[1]
			if strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") {
				if !seen[ref] {
					seen[ref] = true
					refs = append(refs, ref)
				}
			}
		}
	}

	// Full JS URLs found in content (webpack chunks, CDN bundles, etc.)
	for _, match := range jsURLPatterns.FindAllString(content, -1) {
		lower := strings.ToLower(match)
		if strings.HasSuffix(lower, ".js") || strings.Contains(lower, ".js?") ||
			strings.HasSuffix(lower, ".js.map") || strings.HasSuffix(lower, ".map") {
			addRef(match)
		}
	}

	// Webpack/bundler chunk references: "chunk-xxx.js", "vendor.abc123.js"
	for _, m := range jsChunkPattern.FindAllStringSubmatch(content, -1) {
		if len(m) >= 2 {
			addRef(m[1])
		}
	}

	return refs
}

// scanSourceMap parses a .js.map file and extracts endpoints from sourcesContent.
func (jc *jsChainFollower) scanSourceMap(content, basename string) []string {
	jc.mu.Lock()
	jc.sourcemapCount++
	jc.mu.Unlock()

	var sm sourceMap
	if err := json.Unmarshal([]byte(content), &sm); err != nil {
		return nil
	}

	srcURL := jc.sourceURL(basename)

	// Extract endpoints from each source content entry (unminified code)
	for i, src := range sm.SourcesContent {
		if src == "" || len(src) > 10*1024*1024 {
			continue
		}
		// Use source map's original filename for context
		sourceLabel := srcURL
		if i < len(sm.Sources) {
			sourceLabel = srcURL + ":" + filepath.Base(sm.Sources[i])
		}

		// Temporarily set manifest entry so extractEndpoints picks it up
		jc.extractEndpointsWithSource(src, sourceLabel)
	}

	return nil
}

// extractEndpointsWithSource is like extractEndpoints but with explicit source URL.
func (jc *jsChainFollower) extractEndpointsWithSource(content, srcURL string) {
	for _, match := range jsURLPatterns.FindAllString(content, -1) {
		jc.emit(Endpoint{
			URL:        match,
			Method:     "GET",
			Source:     "sourcemap",
			SourceFile: srcURL,
		})
	}

	for _, match := range jsAPIPathPattern.FindAllString(content, -1) {
		match = strings.Trim(match, "\"'`")
		jc.emit(Endpoint{
			URL:        match,
			Method:     "GET",
			Source:     "sourcemap",
			SourceFile: srcURL,
			Context:    "api_path",
		})
	}

	for _, m := range jsFetchPattern.FindAllStringSubmatch(content, -1) {
		if len(m) >= 2 {
			jc.emit(Endpoint{
				URL:        strings.Trim(m[1], "\"'`"),
				Method:     "GET",
				Source:     "sourcemap",
				SourceFile: srcURL,
				Context:    "fetch",
			})
		}
	}

	for _, m := range jsAxiosPattern.FindAllStringSubmatch(content, -1) {
		if len(m) >= 3 {
			jc.emit(Endpoint{
				URL:        strings.Trim(m[2], "\"'`"),
				Method:     strings.ToUpper(m[1]),
				Source:     "sourcemap",
				SourceFile: srcURL,
				Context:    "axios",
			})
		}
	}
}

type sourceMap struct {
	Sources        []string `json:"sources"`
	SourcesContent []string `json:"sourcesContent"`
}

// downloadFile downloads a JS or .map file, deduplicates by SHA256 hash.
func (jc *jsChainFollower) downloadFile(rawURL string) (localPath string, ok bool) {
	req, err := http.NewRequestWithContext(jc.ctx, "GET", rawURL, nil)
	if err != nil {
		return "", false
	}
	req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; recon0/1.0)")

	resp, err := jc.client.Do(req)
	if err != nil {
		return "", false
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return "", false
	}

	// Reject HTML (custom 404 pages)
	ct := resp.Header.Get("Content-Type")
	if strings.Contains(strings.ToLower(ct), "text/html") {
		return "", false
	}

	maxSize := int64(10 * 1024 * 1024)
	if strings.HasSuffix(rawURL, ".map") {
		maxSize = int64(maxSourceMapMB * 1024 * 1024)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxSize))
	if err != nil || len(body) < 20 {
		return "", false
	}

	hash := fmt.Sprintf("%x", sha256.Sum256(body))
	jc.mu.Lock()
	if jc.seenHash[hash] {
		jc.mu.Unlock()
		return "", false
	}
	jc.seenHash[hash] = true
	jc.downloadedCount++
	jc.mu.Unlock()

	filename := hash[:12] + "_" + safeFilenameFromURL(rawURL)
	outPath := filepath.Join(jc.jsDir, filename)
	if err := os.WriteFile(outPath, body, 0644); err != nil {
		return "", false
	}

	// Record in manifest so endpoints get proper source URL
	jc.mu.Lock()
	jc.manifest[filename] = rawURL
	jc.mu.Unlock()

	return outPath, true
}

func safeFilenameFromURL(rawURL string) string {
	path := rawURL
	if idx := strings.Index(path, "?"); idx > 0 {
		path = path[:idx]
	}
	if idx := strings.LastIndex(path, "/"); idx >= 0 {
		path = path[idx+1:]
	}
	path = strings.Map(func(r rune) rune {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' {
			return r
		}
		return '_'
	}, path)
	if len(path) > 100 {
		path = path[:100]
	}
	if path == "" {
		path = "unknown.js"
	}
	return path
}

// ── HAR extraction (unchanged) ──

// extractFromHAR parses a HAR file and emits endpoints from requests.
func (d *Discover) extractFromHAR(harPath string, emit func(Endpoint)) {
	data, err := os.ReadFile(harPath)
	if err != nil {
		return
	}

	var har cdp.HAR
	if err := json.Unmarshal(data, &har); err != nil {
		return
	}

	basename := filepath.Base(harPath)

	for _, entry := range har.Log.Entries {
		reqURL := entry.Request.URL
		if reqURL == "" {
			continue
		}

		// Extract query params + enriched param details
		var params []string
		var paramDetails []ParamDetail
		if parsed, err := url.Parse(reqURL); err == nil {
			for k, vals := range parsed.Query() {
				params = append(params, k)
				v := ""
				if len(vals) > 0 {
					v = vals[0]
				}
				paramDetails = append(paramDetails, ParamDetail{
					Name:  k,
					Value: truncate(v, 100),
					Type:  inferParamType(v),
				})
			}
		}

		// Detect API version pattern
		apiVer, nextVer := detectAPIVersion(reqURL)

		ep := Endpoint{
			URL:          reqURL,
			Method:       entry.Request.Method,
			Source:       "har",
			SourceFile:   basename,
			Params:       params,
			ParamDetails: paramDetails,
			StatusCode:   entry.Response.Status,
			ContentType:  entry.Response.Content.MimeType,
			APIVersion:   apiVer,
			NextVersion:  nextVer,
		}

		// Extract POST body context + field names
		if entry.Request.PostData != nil && entry.Request.PostData.Text != "" {
			ep.Context = truncate(entry.Request.PostData.Text, 200)
			ep.BodyFields = extractPostBodyFields(entry.Request.PostData.Text, entry.Request.PostData.MimeType)
		}

		// Extract interesting response JSON field names
		ct := entry.Response.Content.MimeType
		if strings.Contains(ct, "json") && entry.Response.Content.Text != "" {
			ep.ResponseFields = extractJSONFieldNames(entry.Response.Content.Text)
		}

		emit(ep)

		// Also extract endpoints from HTML responses
		if strings.Contains(ct, "html") && entry.Response.Content.Text != "" {
			extractHTMLEndpoints(entry.Response.Content.Text, reqURL, basename, emit)
		}
	}
}

// extractHTMLEndpoints finds endpoints in HTML content (form actions, link hrefs).
func extractHTMLEndpoints(html, sourceURL, sourceFile string, emit func(Endpoint)) {
	// Form actions
	for _, m := range htmlFormPattern.FindAllStringSubmatch(html, -1) {
		if len(m) >= 2 {
			action := m[1]
			method := "GET"
			if methodMatch := htmlFormMethodPattern.FindStringSubmatch(m[0]); len(methodMatch) >= 2 {
				method = strings.ToUpper(methodMatch[1])
			}
			resolved := resolveURL(sourceURL, action)
			if resolved != "" {
				emit(Endpoint{
					URL:        resolved,
					Method:     method,
					Source:     "html",
					SourceFile: sourceFile,
					Context:    "form",
				})
			}
		}
	}

	// Link hrefs (only interesting paths — API, admin, etc.)
	for _, m := range htmlLinkPattern.FindAllStringSubmatch(html, -1) {
		if len(m) >= 2 {
			href := m[1]
			if isInterestingPath(href) {
				resolved := resolveURL(sourceURL, href)
				if resolved != "" {
					emit(Endpoint{
						URL:        resolved,
						Method:     "GET",
						Source:     "html",
						SourceFile: sourceFile,
						Context:    "link",
					})
				}
			}
		}
	}
}

// resolveURL resolves a relative URL against a base URL.
func resolveURL(base, ref string) string {
	if strings.HasPrefix(ref, "http://") || strings.HasPrefix(ref, "https://") {
		return ref
	}
	if ref == "" || ref == "#" || strings.HasPrefix(ref, "javascript:") || strings.HasPrefix(ref, "mailto:") {
		return ""
	}
	baseURL, err := url.Parse(base)
	if err != nil {
		return ref
	}
	refURL, err := url.Parse(ref)
	if err != nil {
		return ref
	}
	return baseURL.ResolveReference(refURL).String()
}

// isInterestingPath filters HTML links to only include potentially interesting paths.
func isInterestingPath(path string) bool {
	lower := strings.ToLower(path)
	prefixes := []string{
		"/api/", "/v1/", "/v2/", "/v3/",
		"/admin", "/auth", "/login", "/register",
		"/graphql", "/rest/", "/ws/",
		"/debug", "/env", "/config",
		"/swagger", "/openapi", "/docs/api",
		"/actuator", "/metrics", "/health",
		"/.well-known/", "/.env",
	}
	for _, p := range prefixes {
		if strings.Contains(lower, p) {
			return true
		}
	}
	// Paths with file extensions that might contain secrets
	exts := []string{".json", ".xml", ".yaml", ".yml", ".conf", ".cfg", ".bak", ".old", ".sql"}
	for _, ext := range exts {
		if strings.HasSuffix(lower, ext) {
			return true
		}
	}
	return false
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

// ── HAR enrichment helpers ──

var (
	reNumericParam = regexp.MustCompile(`^-?[0-9]+$`)
	reUUIDParam    = regexp.MustCompile(`(?i)^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`)
	reEmailParam   = regexp.MustCompile(`^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	reAPIVersion   = regexp.MustCompile(`/v([0-9]+)/`)
)

// inferParamType classifies a query parameter value.
func inferParamType(value string) string {
	if value == "" {
		return "string"
	}
	if reNumericParam.MatchString(value) {
		return "numeric"
	}
	if reUUIDParam.MatchString(value) {
		return "uuid"
	}
	if reEmailParam.MatchString(value) {
		return "email"
	}
	if strings.HasPrefix(value, "http://") || strings.HasPrefix(value, "https://") {
		return "url"
	}
	lower := strings.ToLower(value)
	if lower == "true" || lower == "false" {
		return "boolean"
	}
	return "string"
}

// detectAPIVersion finds /v1/, /v2/ etc. in a URL and suggests the next version.
func detectAPIVersion(rawURL string) (current, next string) {
	m := reAPIVersion.FindStringSubmatch(rawURL)
	if m == nil {
		return "", ""
	}
	ver, _ := strconv.Atoi(m[1])
	return fmt.Sprintf("v%d", ver), fmt.Sprintf("v%d", ver+1)
}

// interestingResponseFields lists JSON field names that are security-relevant in API responses.
var interestingResponseFields = map[string]bool{
	"id": true, "user_id": true, "userId": true,
	"role": true, "roles": true, "is_admin": true, "isAdmin": true, "admin": true,
	"token": true, "access_token": true, "accessToken": true, "refresh_token": true,
	"secret": true, "api_key": true, "apiKey": true, "api_secret": true,
	"password": true, "passwd": true, "hash": true,
	"email": true, "phone": true, "ssn": true,
	"private_key": true, "privateKey": true,
	"session": true, "session_id": true, "sessionId": true,
	"permissions": true, "scope": true, "scopes": true,
}

// extractJSONFieldNames returns interesting top-level field names from a JSON response body.
func extractJSONFieldNames(jsonStr string) []string {
	if len(jsonStr) < 2 {
		return nil
	}
	var raw map[string]json.RawMessage
	if err := json.Unmarshal([]byte(jsonStr), &raw); err != nil {
		// Try JSON array — inspect first element
		var arr []json.RawMessage
		if json.Unmarshal([]byte(jsonStr), &arr) != nil || len(arr) == 0 {
			return nil
		}
		if json.Unmarshal(arr[0], &raw) != nil {
			return nil
		}
	}
	var result []string
	for k := range raw {
		if interestingResponseFields[k] {
			result = append(result, k)
		}
	}
	if len(result) == 0 {
		return nil
	}
	return result
}

// extractPostBodyFields returns top-level field names from a JSON POST body.
func extractPostBodyFields(body, mimeType string) []string {
	if body == "" || !strings.Contains(mimeType, "json") {
		return nil
	}
	var raw map[string]json.RawMessage
	if json.Unmarshal([]byte(body), &raw) != nil {
		return nil
	}
	names := make([]string, 0, len(raw))
	for k := range raw {
		names = append(names, k)
	}
	if len(names) == 0 {
		return nil
	}
	return names
}

// ── Regex Patterns ──

var (
	// Full URLs in JS (http/https)
	jsURLPatterns = regexp.MustCompile(`https?://[a-zA-Z0-9._\-]+(?:\.[a-zA-Z]{2,})+(?:/[^\s"'\x60<>{}|\\^~\[\]]*)?`)

	// API-style paths in JS
	jsAPIPathPattern = regexp.MustCompile(`["'\x60](/(?:api|v[0-9]+|graphql|rest|auth|admin|ws|socket)[/][^\s"'\x60<>{}]{2,})["'\x60]`)

	// fetch("url") or fetch('url')
	jsFetchPattern = regexp.MustCompile(`fetch\s*\(\s*["'\x60]([^"'\x60]+)["'\x60]`)

	// axios.get("url"), axios.post("url"), etc.
	jsAxiosPattern = regexp.MustCompile(`axios\s*\.\s*(get|post|put|delete|patch|head|options)\s*\(\s*["'\x60]([^"'\x60]+)["'\x60]`)

	// HTML form actions
	htmlFormPattern = regexp.MustCompile(`<form[^>]*action\s*=\s*["']([^"']+)["']`)

	// HTML form method
	htmlFormMethodPattern = regexp.MustCompile(`method\s*=\s*["']([^"']+)["']`)

	// HTML link hrefs
	htmlLinkPattern = regexp.MustCompile(`<a[^>]*href\s*=\s*["']([^"']+)["']`)

	// ── JS import chain patterns ──

	// ES module: import ... from "url"
	jsImportPattern = regexp.MustCompile(`import\s+.*?\s+from\s+["']([^"']+\.js[^"']*)["']`)

	// Dynamic import: import("url")
	jsDynImportPattern = regexp.MustCompile(`import\s*\(\s*["']([^"']+\.js[^"']*)["']\s*\)`)

	// CommonJS: require("url")
	jsRequirePattern = regexp.MustCompile(`require\s*\(\s*["']([^"']+\.js[^"']*)["']\s*\)`)

	// Source map: //# sourceMappingURL=...
	jsSourceMapPattern = regexp.MustCompile(`//[#@]\s*sourceMappingURL\s*=\s*(\S+)`)

	// Webpack/bundler chunk references: "chunk-xxx.js", "vendor.abc.js"
	jsChunkPattern = regexp.MustCompile(`["']([^"']*(?:chunk|bundle|vendor|main|app|runtime)[^"']*\.js(?:\?[^"']*)?)["']`)
)

// isInScope checks if a URL belongs to the target domain or its subdomains.
func isInScope(rawURL, targetDomain string) bool {
	if targetDomain == "" {
		return true // no target = accept all
	}
	parsed, err := url.Parse(rawURL)
	if err != nil {
		return false
	}
	host := strings.ToLower(parsed.Hostname())
	target := strings.ToLower(targetDomain)

	// Exact match or subdomain match
	return host == target || strings.HasSuffix(host, "."+target)
}

func init() { Register(&Discover{}) }
