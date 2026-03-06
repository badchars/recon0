package pipeline

// Stage defines a pipeline stage with its providers and data flow.
type Stage struct {
	Name      string   // "enum", "resolve", etc.
	Desc      string   // human-readable description
	Providers []string // provider names to run
	Parallel  bool     // run providers concurrently
	IsGate    bool     // if true, zero results = stop pipeline
}

// Stages defines the fixed pipeline execution order.
var Stages = []Stage{
	{
		Name:      "enum",
		Desc:      "Subdomain enumeration",
		Providers: []string{"subfinder", "amass"},
		Parallel:  true,
	},
	{
		Name:      "resolve",
		Desc:      "DNS resolution gate",
		Providers: []string{"dnsx"},
		Parallel:  false,
		IsGate:    true,
	},
	{
		Name:      "probe",
		Desc:      "HTTP probing + TLS",
		Providers: []string{"httpx", "tlsx"},
		Parallel:  true,
	},
	{
		Name:      "crawl",
		Desc:      "Browser crawling + HAR capture",
		Providers: []string{"cdpcrawl"},
		Parallel:  false,
	},
	{
		Name:      "portscan",
		Desc:      "Port scanning",
		Providers: []string{"naabu"},
		Parallel:  false,
	},
	{
		Name:      "discover",
		Desc:      "Endpoint discovery from HAR/JS",
		Providers: []string{"discover"},
		Parallel:  false,
	},
	{
		Name:      "analyze",
		Desc:      "Secret/token/endpoint analysis",
		Providers: []string{"analyzer"},
		Parallel:  false,
	},
	{
		Name:      "collect",
		Desc:      "Intelligence aggregation",
		Providers: []string{"collector"},
		Parallel:  false,
	},
	{
		Name:      "vuln",
		Desc:      "Vulnerability scanning",
		Providers: []string{"nuclei", "activeprobe"},
		Parallel:  true,
	},
}

// StageInput returns the input file path for a given stage.
func StageInput(workDir string, stageName string) string {
	switch stageName {
	case "enum":
		return workDir + "/input/domains.txt"
	case "resolve":
		return workDir + "/output/subdomains.txt"
	case "probe":
		return workDir + "/output/alive.txt"
	case "crawl":
		return workDir + "/output/live-hosts.txt"
	case "portscan":
		return workDir + "/output/alive.txt"
	case "discover":
		return workDir + "/har"
	case "analyze":
		return workDir + "/har"
	case "collect":
		return workDir + "/output"
	case "vuln":
		return workDir + "/output/live-hosts.txt"
	default:
		return ""
	}
}

// StageOutput returns the merged output file path for a given stage.
func StageOutput(workDir string, stageName string) string {
	switch stageName {
	case "enum":
		return workDir + "/output/subdomains.txt"
	case "resolve":
		return workDir + "/output/alive.txt"
	case "probe":
		return workDir + "/output/live-hosts.txt"
	case "crawl":
		return workDir + "/output/urls.txt"
	case "portscan":
		return workDir + "/output/ports.txt"
	case "discover":
		return workDir + "/output/endpoints.json"
	case "analyze":
		return workDir + "/output/findings.json"
	case "collect":
		return workDir + "/output/intel.json"
	case "vuln":
		return workDir + "/output/findings.txt"
	default:
		return ""
	}
}
