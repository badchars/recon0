package llm

// Investigation represents a single suspected vulnerability for AI agent verification.
// The AI agent reads investigations.json, accesses the recon0 output directory,
// and verifies each investigation using its own tools.
type Investigation struct {
	ID              string              `json:"id"`
	VulnType        string              `json:"vuln_type"`        // idor, ssrf, exposed_secret, access_control, tech_vuln, misconfiguration, info_disclosure, subdomain_takeover
	Confidence      string              `json:"confidence"`       // high, medium, low
	Severity        string              `json:"severity"`         // critical, high, medium, low, info
	Title           string              `json:"title"`
	Description     string              `json:"description"`
	FoundAt         InvestigationSource `json:"found_at"`
	Evidence        []string            `json:"evidence"`
	Context         InvestigationContext `json:"context"`
	VerifySteps     []string            `json:"verify_steps"`
	Question        string              `json:"question"`
	RelatedFindings []string            `json:"related_findings,omitempty"`
}

// InvestigationSource identifies where the suspected vulnerability was found.
type InvestigationSource struct {
	Source string `json:"source"`          // endpoints.json, findings.json, fuzz-findings.json, httpx
	File   string `json:"file,omitempty"`  // source filename
	URL    string `json:"url,omitempty"`   // full URL or path
	Host   string `json:"host"`
	Line   int    `json:"line,omitempty"`  // line number (JS findings)
	Method string `json:"method,omitempty"`
}

// InvestigationContext provides cross-correlated context for the investigation.
type InvestigationContext struct {
	HostTech         []string `json:"host_tech,omitempty"`
	HostCDN          string   `json:"host_cdn,omitempty"`
	HostServer       string   `json:"host_server,omitempty"`
	AuthSeen         bool     `json:"auth_seen"`
	AuthType         string   `json:"auth_type,omitempty"` // Bearer, Cookie, Basic, API-Key
	SameHostFindings []string `json:"same_host_findings,omitempty"`
	SameFileFindings []string `json:"same_file_findings,omitempty"`
}

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

	// Findings
	Findings []FindingSummary `json:"findings"`

	// Attack surface
	AttackSurface AttackSurface `json:"attack_surface"`

	// Investigations for AI agent
	InvestigationCount int `json:"investigation_count"`
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
