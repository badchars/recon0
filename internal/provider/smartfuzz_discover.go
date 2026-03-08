package provider

import (
	"bufio"
	"encoding/json"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

// discoverFuzzTarget represents a fuzz target derived from discovered endpoints.
type discoverFuzzTarget struct {
	BaseURL  string // e.g. https://api.nasa.gov
	Path     string // fuzz path
	Method   string
	Source   string // "path-sibling" | "extension-swap" | "idor-param"
	RuleID   string
	RuleName string
}

var (
	reNumericSegment = regexp.MustCompile(`^[0-9]+$`)
	reHashSegment    = regexp.MustCompile(`^[a-f0-9]{16,}$`)
	reUUIDSegment    = regexp.MustCompile(`^[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$`)
)

// siblingWords is a small wordlist for path segment fuzzing.
var siblingWords = []string{
	"admin", "internal", "config", "debug", "system", "health",
	"status", "metrics", "monitor", "management", "console",
	"settings", "accounts", "users", "roles", "permissions",
	"keys", "tokens", "secrets", "backup", "backups",
	"logs", "log", "audit", "test", "testing", "staging",
	"dev", "development", "private", "hidden", "api",
	"graphql", "swagger", "docs", "documentation",
	"uploads", "files", "static", "assets", "export",
	"import", "download", "report", "reports", "dashboard",
}

// extensionSwaps maps original extensions to alternatives to try.
var extensionSwaps = map[string][]string{
	".json": {".yaml", ".yml", ".xml", ".bak", ".old", ".json.bak"},
	".yaml": {".json", ".yml", ".xml", ".bak", ".yaml.bak"},
	".yml":  {".json", ".yaml", ".xml", ".bak"},
	".xml":  {".json", ".yaml", ".bak", ".xml.bak"},
	".conf": {".conf.bak", ".conf.old", ".bak"},
	".cfg":  {".cfg.bak", ".cfg.old", ".bak"},
	".ini":  {".ini.bak", ".ini.old", ".bak"},
	".js":   {".js.map"},
	".css":  {".css.map"},
}

// backupExtensions are tried for files without a known extension.
var backupExtensions = []string{".bak", ".old", ".backup", ".save", ".swp", ".orig"}

// ── Pattern Dedup ──

type urlPattern struct {
	BaseURL string // scheme + host
	Pattern string // normalized path (e.g. /api/v2/users/{N})
	Example string // original path for reference
	Method  string
}

// normalizePathSegment replaces dynamic values with placeholders.
func normalizePathSegment(segment string) string {
	if reNumericSegment.MatchString(segment) {
		return "{N}"
	}
	if reUUIDSegment.MatchString(strings.ToLower(segment)) {
		return "{uuid}"
	}
	if reHashSegment.MatchString(strings.ToLower(segment)) {
		return "{hash}"
	}
	return segment
}

// normalizePath converts a URL path to a pattern.
func normalizePath(path string) string {
	parts := strings.Split(strings.Trim(path, "/"), "/")
	normalized := make([]string, len(parts))
	for i, p := range parts {
		normalized[i] = normalizePathSegment(p)
	}
	return "/" + strings.Join(normalized, "/")
}

// deduplicateEndpoints reads endpoints.json and returns unique URL patterns.
func deduplicateEndpoints(endpointsFile string) []urlPattern {
	f, err := os.Open(endpointsFile)
	if err != nil {
		return nil
	}
	defer f.Close()

	seen := make(map[string]bool)
	var patterns []urlPattern

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		var ep struct {
			URL    string `json:"url"`
			Method string `json:"method"`
		}
		if json.Unmarshal(scanner.Bytes(), &ep) != nil || ep.URL == "" {
			continue
		}

		parsed, err := url.Parse(ep.URL)
		if err != nil || parsed.Host == "" {
			continue
		}

		baseURL := parsed.Scheme + "://" + parsed.Host
		normalizedPath := normalizePath(parsed.Path)
		key := ep.Method + " " + baseURL + normalizedPath

		if seen[key] {
			continue
		}
		seen[key] = true

		patterns = append(patterns, urlPattern{
			BaseURL: baseURL,
			Pattern: normalizedPath,
			Example: parsed.Path,
			Method:  ep.Method,
		})
	}

	return patterns
}

// ── Fuzz Target Generation ──

// generateDiscoveryFuzzTargets creates fuzz targets from discovered endpoints.
func generateDiscoveryFuzzTargets(workDir string) []discoverFuzzTarget {
	endpointsFile := filepath.Join(workDir, "output", "endpoints.json")
	patterns := deduplicateEndpoints(endpointsFile)
	if len(patterns) == 0 {
		return nil
	}

	var targets []discoverFuzzTarget

	// Cap total generated targets
	maxTargets := 2000

	for _, p := range patterns {
		if len(targets) >= maxTargets {
			break
		}

		// 1. Path segment fuzzing (sibling discovery)
		targets = append(targets, generateSiblingTargets(p)...)

		// 2. Extension swap
		targets = append(targets, generateExtensionSwapTargets(p)...)
	}

	// Deduplicate
	seen := make(map[string]bool)
	var deduped []discoverFuzzTarget
	for _, t := range targets {
		key := t.BaseURL + t.Path
		if !seen[key] {
			seen[key] = true
			deduped = append(deduped, t)
		}
	}

	return deduped
}

// generateSiblingTargets finds fuzzable path segments and generates siblings.
func generateSiblingTargets(p urlPattern) []discoverFuzzTarget {
	parts := strings.Split(strings.Trim(p.Pattern, "/"), "/")
	if len(parts) < 2 {
		return nil
	}

	var targets []discoverFuzzTarget

	// Find the last non-placeholder segment and fuzz it
	for i := len(parts) - 1; i >= 0; i-- {
		if parts[i] == "{N}" || parts[i] == "{uuid}" || parts[i] == "{hash}" {
			continue
		}

		// This is a real segment — try siblings
		for _, word := range siblingWords {
			if strings.EqualFold(word, parts[i]) {
				continue // skip same word
			}

			newParts := make([]string, len(parts))
			copy(newParts, parts)
			newParts[i] = word
			newPath := "/" + strings.Join(newParts, "/")

			targets = append(targets, discoverFuzzTarget{
				BaseURL:  p.BaseURL,
				Path:     newPath,
				Method:   "GET",
				Source:   "path-sibling",
				RuleID:   "discovery-path-sibling",
				RuleName: "API Endpoint Discovery (Sibling)",
			})
		}

		break // only fuzz one segment
	}

	return targets
}

// generateExtensionSwapTargets tries alternative file extensions.
func generateExtensionSwapTargets(p urlPattern) []discoverFuzzTarget {
	ext := filepath.Ext(p.Example)
	if ext == "" {
		return nil
	}

	var targets []discoverFuzzTarget
	basePath := strings.TrimSuffix(p.Example, ext)

	if swaps, ok := extensionSwaps[ext]; ok {
		for _, newExt := range swaps {
			targets = append(targets, discoverFuzzTarget{
				BaseURL:  p.BaseURL,
				Path:     basePath + newExt,
				Method:   "GET",
				Source:   "extension-swap",
				RuleID:   "discovery-extension-swap",
				RuleName: "File Extension Swap Discovery",
			})
		}
	} else {
		// Unknown extension — try backup variants
		for _, bak := range backupExtensions {
			targets = append(targets, discoverFuzzTarget{
				BaseURL:  p.BaseURL,
				Path:     p.Example + bak,
				Method:   "GET",
				Source:   "extension-swap",
				RuleID:   "discovery-backup-file",
				RuleName: "Backup File Discovery",
			})
		}
	}

	return targets
}
