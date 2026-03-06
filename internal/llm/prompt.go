package llm

import (
	"encoding/json"
	"fmt"
	"strings"
)

// IntelligenceReport is the structured output of the collector.
type IntelligenceReport struct {
	Target      string `json:"target"`
	GeneratedAt string `json:"generated_at"`

	// Summary counts
	SubdomainCount int `json:"subdomain_count"`
	LiveHostCount  int `json:"live_host_count"`
	OpenPortCount  int `json:"open_port_count"`
	EndpointCount  int `json:"endpoint_count"`

	// Detailed asset inventory
	Hosts []HostInfo `json:"hosts"`

	// Findings and attack surface
	Findings      []FindingSummary `json:"findings"`
	AttackSurface AttackSurface    `json:"attack_surface"`

	// LLM output
	Recommendations []string `json:"recommendations,omitempty"`
	LLMAnalysis     *string  `json:"llm_analysis,omitempty"`
}

// HostInfo combines httpx/tlsx/naabu data for a single host.
type HostInfo struct {
	Host       string   `json:"host"`
	URL        string   `json:"url,omitempty"`
	IP         string   `json:"ip,omitempty"`
	StatusCode int      `json:"status_code,omitempty"`
	Tech       []string `json:"tech,omitempty"`
	CDN        string   `json:"cdn,omitempty"`
	TLSVersion string   `json:"tls_version,omitempty"`
	TLSIssuer  string   `json:"tls_issuer,omitempty"`
	TLSExpiry  string   `json:"tls_expiry,omitempty"`
	Wildcard   bool     `json:"wildcard_cert,omitempty"`
	CNAME      []string `json:"cname,omitempty"`
	Ports      []int    `json:"ports,omitempty"`
	FinalURL   string   `json:"final_url,omitempty"`
	Server     string   `json:"server,omitempty"`
}

// FindingSummary is a condensed finding for the report.
type FindingSummary struct {
	RuleID   string `json:"rule_id"`
	RuleName string `json:"rule_name"`
	Severity string `json:"severity"`
	Value    string `json:"value"`
	Source   string `json:"source"`
	File     string `json:"file,omitempty"`
	URL      string `json:"url,omitempty"`
}

// AttackSurface categorizes the discovered attack surface.
type AttackSurface struct {
	APIEndpoints     []string `json:"api_endpoints,omitempty"`
	AdminPanels      []string `json:"admin_panels,omitempty"`
	ExposedFiles     []string `json:"exposed_files,omitempty"`
	InterestingPorts []string `json:"interesting_ports,omitempty"`
}

// BuildAnalysisPrompt creates a prompt for LLM analysis of the intelligence report.
func BuildAnalysisPrompt(report *IntelligenceReport) []Message {
	// Build a focused summary for the LLM (avoid dumping entire JSON for large scans)
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("# Recon Intelligence Report: %s\n\n", report.Target))
	sb.WriteString(fmt.Sprintf("Generated: %s\n", report.GeneratedAt))
	sb.WriteString(fmt.Sprintf("Subdomains: %d | Live Hosts: %d | Open Ports: %d | Endpoints: %d\n\n",
		report.SubdomainCount, report.LiveHostCount, report.OpenPortCount, report.EndpointCount))

	// Host inventory
	sb.WriteString("## Host Inventory\n\n")
	for _, h := range report.Hosts {
		sb.WriteString(fmt.Sprintf("### %s\n", h.Host))
		if h.URL != "" {
			sb.WriteString(fmt.Sprintf("- URL: %s\n", h.URL))
		}
		if h.IP != "" {
			sb.WriteString(fmt.Sprintf("- IP: %s\n", h.IP))
		}
		if h.StatusCode > 0 {
			sb.WriteString(fmt.Sprintf("- Status: %d\n", h.StatusCode))
		}
		if len(h.Tech) > 0 {
			sb.WriteString(fmt.Sprintf("- Tech: %s\n", strings.Join(h.Tech, ", ")))
		}
		if h.CDN != "" {
			sb.WriteString(fmt.Sprintf("- CDN: %s\n", h.CDN))
		}
		if h.Server != "" {
			sb.WriteString(fmt.Sprintf("- Server: %s\n", h.Server))
		}
		if h.TLSVersion != "" {
			sb.WriteString(fmt.Sprintf("- TLS: %s (issuer: %s, expires: %s", h.TLSVersion, h.TLSIssuer, h.TLSExpiry))
			if h.Wildcard {
				sb.WriteString(", wildcard cert")
			}
			sb.WriteString(")\n")
		}
		if len(h.CNAME) > 0 {
			sb.WriteString(fmt.Sprintf("- CNAME: %s\n", strings.Join(h.CNAME, " → ")))
		}
		if len(h.Ports) > 0 {
			portStrs := make([]string, len(h.Ports))
			for i, p := range h.Ports {
				portStrs[i] = fmt.Sprintf("%d", p)
			}
			sb.WriteString(fmt.Sprintf("- Open Ports: %s\n", strings.Join(portStrs, ", ")))
		}
		if h.FinalURL != "" && h.FinalURL != h.URL {
			sb.WriteString(fmt.Sprintf("- Redirects to: %s\n", h.FinalURL))
		}
		sb.WriteString("\n")
	}

	// Findings by severity
	sb.WriteString("## Findings\n\n")
	for _, sev := range []string{"critical", "high", "medium", "low", "info"} {
		var sevFindings []FindingSummary
		for _, f := range report.Findings {
			if f.Severity == sev {
				sevFindings = append(sevFindings, f)
			}
		}
		if len(sevFindings) == 0 {
			continue
		}
		sb.WriteString(fmt.Sprintf("### %s (%d)\n", strings.ToUpper(sev), len(sevFindings)))
		for _, f := range sevFindings {
			val := f.Value
			if len(val) > 120 {
				val = val[:120] + "..."
			}
			sb.WriteString(fmt.Sprintf("- **%s** (%s): `%s`\n", f.RuleName, f.RuleID, val))
			if f.URL != "" {
				sb.WriteString(fmt.Sprintf("  Source URL: %s\n", f.URL))
			} else if f.File != "" {
				sb.WriteString(fmt.Sprintf("  Source file: %s\n", f.File))
			}
		}
		sb.WriteString("\n")
	}

	// Attack surface
	sb.WriteString("## Attack Surface\n\n")
	if len(report.AttackSurface.APIEndpoints) > 0 {
		sb.WriteString("### API Endpoints\n")
		for _, ep := range report.AttackSurface.APIEndpoints {
			sb.WriteString(fmt.Sprintf("- %s\n", ep))
		}
		sb.WriteString("\n")
	}
	if len(report.AttackSurface.AdminPanels) > 0 {
		sb.WriteString("### Admin Panels\n")
		for _, p := range report.AttackSurface.AdminPanels {
			sb.WriteString(fmt.Sprintf("- %s\n", p))
		}
		sb.WriteString("\n")
	}
	if len(report.AttackSurface.ExposedFiles) > 0 {
		sb.WriteString("### Exposed Files\n")
		for _, f := range report.AttackSurface.ExposedFiles {
			sb.WriteString(fmt.Sprintf("- %s\n", f))
		}
		sb.WriteString("\n")
	}

	systemPrompt := `You are a senior penetration tester analyzing reconnaissance data from an authorized security assessment. Analyze the data and provide:

1. **Critical Findings** — Which findings are most likely real and exploitable? Correlate findings with the host inventory (e.g. a secret found in a JS file on host X running technology Y).
2. **False Positive Assessment** — Which findings are likely false positives and why? Use context like the tech stack, CDN, and source URL to determine.
3. **Attack Scenarios** — Based on the host inventory, tech stack, attack surface, and findings, describe the top 3-5 attack paths. Be specific about which hosts and endpoints to target.
4. **Subdomain Takeover Risk** — Check CNAME records for dangling references or third-party services that might be vulnerable.
5. **Recommendations** — Prioritized list of what to test next, including specific hosts and endpoints.

Be concise, technical, and actionable. Reference specific hosts, URLs, and findings.`

	return []Message{
		{Role: "system", Content: systemPrompt},
		{Role: "user", Content: sb.String()},
	}
}

// ParseLLMResponse extracts recommendations from the LLM response.
func ParseLLMResponse(response string, report *IntelligenceReport) {
	report.LLMAnalysis = &response

	// Extract recommendations section
	lines := strings.Split(response, "\n")
	inRecommendations := false
	for _, line := range lines {
		lower := strings.ToLower(line)
		if strings.Contains(lower, "recommendation") {
			inRecommendations = true
			continue
		}
		if inRecommendations && strings.HasPrefix(strings.TrimSpace(line), "- ") {
			rec := strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(line), "- "))
			if rec != "" {
				report.Recommendations = append(report.Recommendations, rec)
			}
		}
		if inRecommendations && line == "" && len(report.Recommendations) > 0 {
			inRecommendations = false
		}
	}
}

// Legacy compat — used by collector for backward compatibility
// Deprecated fields mapped to new names
func (r *IntelligenceReport) SetLegacyCounts(subdomains, liveHosts, openPorts, endpoints int) {
	r.SubdomainCount = subdomains
	r.LiveHostCount = liveHosts
	r.OpenPortCount = openPorts
	r.EndpointCount = endpoints
}

// MarshalForReport returns JSON for the full report file (intel.json).
func MarshalForReport(report *IntelligenceReport) ([]byte, error) {
	return json.MarshalIndent(report, "", "  ")
}
