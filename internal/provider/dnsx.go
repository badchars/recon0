package provider

import (
	"bufio"
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
)

type Dnsx struct{}

func (d *Dnsx) Name() string       { return "dnsx" }
func (d *Dnsx) Stage() string      { return "resolve" }
func (d *Dnsx) OutputType() string { return "resolved" }
func (d *Dnsx) Check() error       { return CheckBinary("dnsx") }

func (d *Dnsx) Run(ctx context.Context, opts *RunOpts) (*Result, error) {
	jsonOut := opts.Output + ".json"

	// Detect wildcard domains before resolution
	wildcardDomains := detectWildcards(ctx, opts.Input)

	args := []string{
		"-l", opts.Input,
		"-a", "-aaaa", "-cname", "-mx", "-ns", "-txt", "-soa", "-ptr",
		"-re",
		"-cdn",
		"-asn",
		"-t", strconv.Itoa(opts.Res.ThreadsDNS),
		"-retry", "3",
		"-json", "-o", jsonOut,
	}

	// Enable wildcard filtering for detected wildcard domains
	if len(wildcardDomains) > 0 {
		for _, wd := range wildcardDomains {
			args = append(args, "-wd", wd)
		}
		// Write wildcard domains to a file for reference
		wcFile := filepath.Join(opts.WorkDir, "raw", "wildcard-domains.txt")
		writeLines(wcFile, wildcardDomains)
	}

	cmd := exec.CommandContext(ctx, "dnsx", args...)
	errFile, err := OpenLogFile(opts.LogDir, "dnsx")
	if err == nil {
		defer errFile.Close()
		cmd.Stderr = errFile
	}

	if err := cmd.Run(); err != nil {
		return &Result{OutputFile: opts.Output}, fmt.Errorf("dnsx: %w", err)
	}

	// Extract alive hosts from JSON
	alive, err := extractJSONField(jsonOut, "host")
	if err != nil {
		return &Result{OutputFile: opts.Output}, fmt.Errorf("dnsx parse: %w", err)
	}
	writeLines(opts.Output, alive)

	// Compute dead subdomains
	inputHosts := readLines(opts.Input)
	aliveSet := toSet(alive)
	var dead []string
	for _, h := range inputHosts {
		if _, ok := aliveSet[h]; !ok {
			dead = append(dead, h)
		}
	}
	deadFile := strings.TrimSuffix(opts.Output, ".txt") + "-dead.txt"
	writeLines(deadFile, dead)

	// Subdomain takeover check on dead CNAMEs
	takeoverCount := 0
	if len(dead) > 0 {
		takeoverCount = d.checkTakeover(ctx, opts, dead, jsonOut)
	}

	extra := map[string]any{
		"alive":               len(alive),
		"dead":                len(dead),
		"takeover_candidates": takeoverCount,
	}

	return &Result{
		Count:      len(alive),
		OutputFile: opts.Output,
		Extra:      extra,
	}, nil
}

func (d *Dnsx) checkTakeover(ctx context.Context, opts *RunOpts, dead []string, jsonOut string) int {
	takeoverPatterns := []string{
		"s3.amazonaws", "github.io", "herokuapp.com", "azurewebsites.net",
		"cloudapp.net", "trafficmanager.net", "blob.core.windows.net",
		"azure-api.net", "azureedge.net", "azurefd.net",
		"ghost.io", "myshopify.com", "surge.sh", "bitbucket.io",
		"tumblr.com", "wordpress.com", "pantheonsite.io",
		"statuspage.io", "zendesk.com", "readme.io",
		"fly.dev", "netlify.app", "vercel.app", "pages.dev", "render.com",
	}

	// Check all CNAMEs from JSON output for dangling references
	takeoverFile := filepath.Join(opts.WorkDir, "raw", "takeover-candidates.txt")
	var candidates []string

	// Read CNAMEs from the full JSON output
	f, err := os.Open(jsonOut)
	if err != nil {
		return 0
	}
	defer f.Close()

	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	deadSet := toSet(dead)

	for scanner.Scan() {
		line := scanner.Text()
		// Quick check: does this line have a cname field?
		if !strings.Contains(line, "cname") {
			continue
		}
		// Extract host from line
		host := extractInlineField(line, "host")
		if host == "" {
			continue
		}

		for _, pattern := range takeoverPatterns {
			if strings.Contains(strings.ToLower(line), pattern) {
				prefix := ""
				if _, isDead := deadSet[host]; isDead {
					prefix = "[DEAD] "
				}
				candidates = append(candidates, fmt.Sprintf("%s%s -> %s", prefix, host, pattern))
				break
			}
		}
	}

	if len(candidates) > 0 {
		writeLines(takeoverFile, candidates)

		// Run nuclei takeover templates if available
		nucleiPath, err := exec.LookPath("nuclei")
		if err == nil {
			takeoverHosts := filepath.Join(opts.WorkDir, "raw", "takeover-hosts.txt")
			var hosts []string
			for _, c := range candidates {
				parts := strings.Fields(c)
				if len(parts) > 0 {
					h := strings.TrimPrefix(parts[0], "[DEAD] ")
					hosts = append(hosts, h)
				}
			}
			writeLines(takeoverHosts, unique(hosts))

			findingsFile := filepath.Join(opts.WorkDir, "raw", "takeover-findings.txt")
			cmd := exec.CommandContext(ctx, nucleiPath,
				"-l", takeoverHosts,
				"-tags", "takeover",
				"-j", "-o", findingsFile,
				"-silent",
			)
			cmd.Run() // best-effort
		}
	}

	return len(candidates)
}

// ── wildcard detection ──

// detectWildcards checks root domains for wildcard DNS.
// Returns domains with wildcard and a map of domain→wildcard IPs.
//
// How it works:
//   1. Resolve 3 random subdomains per root domain (e.g. xq7z9k2m4w.example.com)
//   2. If 2+ resolve → wildcard detected
//   3. Collect the IPs they resolve to → these are "wildcard IPs"
//   4. dnsx -wd flag will filter subdomains resolving to wildcard IPs
//   5. Subdomains resolving to DIFFERENT IPs pass through → real services
func detectWildcards(ctx context.Context, inputFile string) []string {
	subs := readLines(inputFile)
	roots := map[string]bool{}
	for _, s := range subs {
		parts := strings.Split(s, ".")
		if len(parts) >= 2 {
			root := strings.Join(parts[len(parts)-2:], ".")
			roots[root] = true
		}
	}

	var wildcards []string
	for root := range roots {
		if ctx.Err() != nil {
			break
		}
		randoms := []string{
			fmt.Sprintf("xq7z9k2m4w.%s", root),
			fmt.Sprintf("p3j8v5n1f6.%s", root),
			fmt.Sprintf("a9c2e7g4i0.%s", root),
		}
		resolved := 0
		for _, r := range randoms {
			cmd := exec.CommandContext(ctx, "dnsx", "-d", r, "-a", "-resp-only", "-silent", "-retry", "1", "-t", "1")
			out, err := cmd.Output()
			if err == nil && len(strings.TrimSpace(string(out))) > 0 {
				resolved++
			}
		}
		if resolved >= 2 {
			wildcards = append(wildcards, root)
		}
	}

	return wildcards
}

// ── helpers ──

func extractJSONField(jsonFile, field string) ([]string, error) {
	f, err := os.Open(jsonFile)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	seen := map[string]bool{}
	var result []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)

	key := fmt.Sprintf(`"%s"`, field)
	for scanner.Scan() {
		line := scanner.Text()
		val := extractInlineField(line, field)
		if val != "" && !seen[val] {
			seen[val] = true
			result = append(result, val)
		}
		_ = key
	}
	return result, nil
}

func extractInlineField(jsonLine, field string) string {
	key := fmt.Sprintf(`"%s":"`, field)
	idx := strings.Index(jsonLine, key)
	if idx < 0 {
		key = fmt.Sprintf(`"%s": "`, field)
		idx = strings.Index(jsonLine, key)
	}
	if idx < 0 {
		return ""
	}
	start := idx + len(key)
	end := strings.Index(jsonLine[start:], `"`)
	if end < 0 {
		return ""
	}
	return jsonLine[start : start+end]
}

func readLines(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer f.Close()
	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		if line := strings.TrimSpace(scanner.Text()); line != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

func writeLines(path string, lines []string) {
	os.MkdirAll(filepath.Dir(path), 0755)
	f, err := os.Create(path)
	if err != nil {
		return
	}
	defer f.Close()
	for _, l := range lines {
		fmt.Fprintln(f, l)
	}
}

func toSet(lines []string) map[string]struct{} {
	m := make(map[string]struct{}, len(lines))
	for _, l := range lines {
		m[l] = struct{}{}
	}
	return m
}

func unique(lines []string) []string {
	seen := map[string]bool{}
	var result []string
	for _, l := range lines {
		if !seen[l] {
			seen[l] = true
			result = append(result, l)
		}
	}
	return result
}

func init() { Register(&Dnsx{}) }
