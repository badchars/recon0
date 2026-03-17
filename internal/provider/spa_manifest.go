package provider

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// spaFrameworkInfo holds detected SPA framework metadata for a given origin.
type spaFrameworkInfo struct {
	Framework     string // "nextjs", "angular", "nuxt", "vite"
	Origin        string // e.g., "https://helpers.bullsheet.me"
	BuildID       string // Next.js buildId extracted from /_next/static/<buildId>/
	PublicPath    string // webpack publicPath, e.g., "/_next/"
	ChunkTemplate string // e.g., "static/chunks/{ID}.hash.js"
}

// Regex patterns for SPA framework detection and manifest parsing.
var (
	reNextBuildID       = regexp.MustCompile(`/_next/static/([a-zA-Z0-9_-]{8,})/`)
	reNextChunks        = regexp.MustCompile(`/_next/static/chunks/`)
	reWebpackPublicPath = regexp.MustCompile(`\.p\s*=\s*["']([^"']+?)["']`)
	reWebpackChunkTmpl  = regexp.MustCompile(`\.u\s*=\s*function\s*\(\s*\w+\s*\)\s*\{\s*return\s*["']([^"']*?)["']\s*\+\s*\w+\s*\+\s*["']([^"']*?)["']`)
	reManifestRoute     = regexp.MustCompile(`["'](/[^"']*?)["']\s*:\s*\[((?:\s*["'][^"']+["']\s*,?\s*)*)\]`)
	reManifestChunk     = regexp.MustCompile(`["']([^"']+\.js)["']`)
	reChunkHashPair     = regexp.MustCompile(`(\d+)\s*:\s*"([a-f0-9]+)"`)
	reWebpackChunkMap   = regexp.MustCompile(`\{((?:\d+\s*:\s*"[a-f0-9]+"\s*,?\s*)+)\}`)
)

// discoverSPAManifests detects SPA frameworks from existing JS files and fetches
// their build manifests to discover hidden route-based JS chunks.
func (jc *jsChainFollower) discoverSPAManifests() []jsQueueItem {
	jc.detectSPAFrameworks()

	if len(jc.detectedSPA) == 0 {
		return nil
	}

	var queue []jsQueueItem
	for origin, info := range jc.detectedSPA {
		if jc.ctx.Err() != nil {
			break
		}
		fmt.Fprintf(os.Stderr, "[discover] SPA detected: %s (%s)\n", origin, info.Framework)
		items := jc.fetchSPAManifest(info)
		queue = append(queue, items...)
	}
	return queue
}

// detectSPAFrameworks scans the JS manifest URL map and file contents for known
// SPA framework signatures.
func (jc *jsChainFollower) detectSPAFrameworks() {
	// Strategy 1: Detect from URL patterns in the manifest
	for _, jsURL := range jc.manifest {
		origin := extractOrigin(jsURL)
		if origin == "" {
			continue
		}

		// Next.js: /_next/static/<buildId>/
		if m := reNextBuildID.FindStringSubmatch(jsURL); m != nil {
			existing, ok := jc.detectedSPA[origin]
			if !ok {
				jc.detectedSPA[origin] = &spaFrameworkInfo{
					Framework:  "nextjs",
					Origin:     origin,
					BuildID:    m[1],
					PublicPath: "/_next/",
				}
			} else if existing.BuildID == "" {
				existing.BuildID = m[1]
			}
			continue
		}
		// Next.js: /_next/static/chunks/ (no buildId)
		if _, ok := jc.detectedSPA[origin]; !ok && reNextChunks.MatchString(jsURL) {
			jc.detectedSPA[origin] = &spaFrameworkInfo{
				Framework:  "nextjs",
				Origin:     origin,
				PublicPath: "/_next/",
			}
		}
	}

	// Strategy 2: Scan file contents for framework markers (only for origins not yet detected)
	for filename, jsURL := range jc.manifest {
		origin := extractOrigin(jsURL)
		if origin == "" {
			continue
		}
		if _, ok := jc.detectedSPA[origin]; ok {
			continue
		}

		filePath := filepath.Join(jc.jsDir, filename)
		data, err := os.ReadFile(filePath)
		if err != nil || len(data) > 5*1024*1024 {
			continue
		}
		content := string(data)

		switch {
		case strings.Contains(content, "__NEXT_DATA__") ||
			strings.Contains(content, "next/router") ||
			strings.Contains(content, "_N_E"):
			jc.detectedSPA[origin] = &spaFrameworkInfo{
				Framework:  "nextjs",
				Origin:     origin,
				PublicPath: "/_next/",
			}
		case strings.Contains(content, "ng-version") ||
			strings.Contains(content, "@angular/core"):
			jc.detectedSPA[origin] = &spaFrameworkInfo{
				Framework: "angular",
				Origin:    origin,
			}
		case strings.Contains(content, "__NUXT__"):
			jc.detectedSPA[origin] = &spaFrameworkInfo{
				Framework: "nuxt",
				Origin:    origin,
			}
		}
	}

	// Strategy 3: Extract webpack chunk templates from runtime files
	jc.extractWebpackChunkTemplates()
}

// extractWebpackChunkTemplates parses webpack runtime JS files for public path and
// chunk URL template patterns.
func (jc *jsChainFollower) extractWebpackChunkTemplates() {
	for filename, jsURL := range jc.manifest {
		origin := extractOrigin(jsURL)
		info, ok := jc.detectedSPA[origin]
		if !ok {
			continue
		}

		basename := filepath.Base(filename)
		if !strings.Contains(basename, "webpack") && !strings.Contains(basename, "runtime") {
			continue
		}

		filePath := filepath.Join(jc.jsDir, filename)
		data, err := os.ReadFile(filePath)
		if err != nil {
			continue
		}
		content := string(data)

		if m := reWebpackPublicPath.FindStringSubmatch(content); m != nil {
			info.PublicPath = m[1]
		}
		if m := reWebpackChunkTmpl.FindStringSubmatch(content); m != nil {
			info.ChunkTemplate = m[1] + "{ID}" + m[2]
		}
	}
}

// fetchSPAManifest dispatches to framework-specific manifest fetching.
func (jc *jsChainFollower) fetchSPAManifest(info *spaFrameworkInfo) []jsQueueItem {
	switch info.Framework {
	case "nextjs":
		return jc.fetchNextJSManifest(info)
	default:
		return nil
	}
}

// fetchNextJSManifest fetches and parses the Next.js _buildManifest.js to discover
// all route-based JS chunks.
func (jc *jsChainFollower) fetchNextJSManifest(info *spaFrameworkInfo) []jsQueueItem {
	var queue []jsQueueItem

	candidates := jc.nextjsBuildManifestURLs(info)
	for _, manifestURL := range candidates {
		if jc.ctx.Err() != nil || jc.downloadedCount >= maxJSDownloads {
			break
		}

		localPath, downloaded := jc.downloadFile(manifestURL)
		if !downloaded || localPath == "" {
			continue
		}

		jc.mu.Lock()
		jc.manifestCount++
		jc.mu.Unlock()

		data, err := os.ReadFile(localPath)
		if err != nil {
			continue
		}

		chunkURLs := parseNextJSBuildManifest(string(data), info.Origin)
		fmt.Fprintf(os.Stderr, "[discover] Next.js _buildManifest: %s → %d chunk URLs\n",
			info.Origin, len(chunkURLs))

		for _, chunkURL := range chunkURLs {
			queue = append(queue, jsQueueItem{url: chunkURL, depth: 1})
		}
		break // found a working manifest
	}

	// Also try constructing chunk URLs from webpack chunk maps
	wpChunks := jc.constructWebpackChunkURLs(info)
	for _, chunkURL := range wpChunks {
		queue = append(queue, jsQueueItem{url: chunkURL, depth: 1})
	}

	return queue
}

// nextjsBuildManifestURLs generates candidate URLs for the Next.js _buildManifest.js.
func (jc *jsChainFollower) nextjsBuildManifestURLs(info *spaFrameworkInfo) []string {
	seen := make(map[string]bool)
	var urls []string

	add := func(u string) {
		if !seen[u] {
			seen[u] = true
			urls = append(urls, u)
		}
	}

	// From known buildId
	if info.BuildID != "" {
		add(info.Origin + "/_next/static/" + info.BuildID + "/_buildManifest.js")
		add(info.Origin + "/_next/static/" + info.BuildID + "/_ssgManifest.js")
	}

	// Extract buildId from other JS URLs in the manifest
	for _, jsURL := range jc.manifest {
		if !strings.HasPrefix(jsURL, info.Origin) {
			continue
		}
		if m := reNextBuildID.FindStringSubmatch(jsURL); m != nil {
			bid := m[1]
			add(info.Origin + "/_next/static/" + bid + "/_buildManifest.js")
			add(info.Origin + "/_next/static/" + bid + "/_ssgManifest.js")
		}
	}

	// Extract buildId from HAR HTML responses
	for _, bid := range jc.extractBuildIDFromHAR(info.Origin) {
		add(info.Origin + "/_next/static/" + bid + "/_buildManifest.js")
		add(info.Origin + "/_next/static/" + bid + "/_ssgManifest.js")
	}

	return urls
}

// extractBuildIDFromHAR scans HAR files for Next.js buildId references in HTML content.
func (jc *jsChainFollower) extractBuildIDFromHAR(origin string) []string {
	harDir := filepath.Join(filepath.Dir(jc.jsDir), "har")
	harFiles, _ := filepath.Glob(filepath.Join(harDir, "*.har"))

	seen := make(map[string]bool)
	var buildIDs []string

	for _, harFile := range harFiles {
		data, err := os.ReadFile(harFile)
		if err != nil {
			continue
		}
		content := string(data)
		if !strings.Contains(content, origin) {
			continue
		}

		// Look for _buildManifest.js or _ssgManifest.js references with buildId
		reBuildRef := regexp.MustCompile(`/_next/static/([a-zA-Z0-9_-]{8,})/(?:_buildManifest|_ssgManifest)\.js`)
		for _, m := range reBuildRef.FindAllStringSubmatch(content, -1) {
			if !seen[m[1]] {
				seen[m[1]] = true
				buildIDs = append(buildIDs, m[1])
			}
		}
	}
	return buildIDs
}

// harEntry is a minimal HAR entry structure for parsing.
type harEntryForSPA struct {
	Log struct {
		Entries []struct {
			Request struct {
				URL string `json:"url"`
			} `json:"request"`
			Response struct {
				Content struct {
					Text     string `json:"text"`
					MimeType string `json:"mimeType"`
				} `json:"content"`
			} `json:"response"`
		} `json:"entries"`
	} `json:"log"`
}

// parseNextJSBuildManifest parses the _buildManifest.js content and extracts all
// route-specific JS chunk URLs.
func parseNextJSBuildManifest(content, origin string) []string {
	seen := make(map[string]bool)
	var chunkURLs []string

	addChunk := func(chunkPath string) {
		chunkPath = strings.TrimPrefix(chunkPath, "/")
		fullURL := origin + "/_next/" + chunkPath
		if !seen[fullURL] {
			seen[fullURL] = true
			chunkURLs = append(chunkURLs, fullURL)
		}
	}

	// Parse route → chunks mapping from manifest
	for _, rm := range reManifestRoute.FindAllStringSubmatch(content, -1) {
		chunkList := rm[2]
		for _, cm := range reManifestChunk.FindAllStringSubmatch(chunkList, -1) {
			addChunk(cm[1])
		}
	}

	return chunkURLs
}

// constructWebpackChunkURLs builds chunk URLs from webpack runtime chunk hash maps.
func (jc *jsChainFollower) constructWebpackChunkURLs(info *spaFrameworkInfo) []string {
	if info.ChunkTemplate == "" || info.PublicPath == "" {
		return nil
	}

	seen := make(map[string]bool)
	var urls []string

	for filename := range jc.manifest {
		filePath := filepath.Join(jc.jsDir, filename)
		data, err := os.ReadFile(filePath)
		if err != nil || len(data) > 5*1024*1024 {
			continue
		}
		content := string(data)

		for _, m := range reWebpackChunkMap.FindAllStringSubmatch(content, -1) {
			pairs := parseChunkHashPairs(m[1])
			for chunkID, hash := range pairs {
				chunkPath := strings.Replace(info.ChunkTemplate, "{ID}", chunkID+"."+hash, 1)
				chunkURL := info.Origin + info.PublicPath + chunkPath
				if !seen[chunkURL] {
					seen[chunkURL] = true
					urls = append(urls, chunkURL)
				}
			}
		}
	}

	if len(urls) > 0 {
		fmt.Fprintf(os.Stderr, "[discover] webpack chunk map: %s → %d chunk URLs\n",
			info.Origin, len(urls))
	}
	return urls
}

// parseChunkHashPairs parses webpack chunk hash map entries like: 123:"abc123",456:"def456"
func parseChunkHashPairs(raw string) map[string]string {
	result := make(map[string]string)
	for _, m := range reChunkHashPair.FindAllStringSubmatch(raw, -1) {
		result[m[1]] = m[2]
	}
	return result
}

// extractOrigin returns the scheme+host portion of a URL.
func extractOrigin(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" {
		return ""
	}
	return u.Scheme + "://" + u.Host
}

// saveManifest writes the updated JS manifest back to disk.
func (jc *jsChainFollower) saveManifest() {
	manifestPath := filepath.Join(jc.jsDir, "_manifest.json")
	data, err := json.MarshalIndent(jc.manifest, "", "  ")
	if err != nil {
		return
	}
	_ = os.WriteFile(manifestPath, data, 0644)
}
