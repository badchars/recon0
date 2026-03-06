package provider

// Probe defines a single HTTP probe to send to a host.
type Probe struct {
	Path         string            // URL path to probe
	Method       string            // HTTP method (default: GET)
	Headers      map[string]string // additional headers
	Body         string            // request body (for POST)
	ExpectStatus []int             // expected status codes (any match = potential hit)
	ExpectBody   []string          // strings to look for in body (any match = hit)
	RejectBody   []string          // false positive filter (any match = skip)
	Severity     string            // critical, high, medium, low, info
	RuleID       string            // unique rule identifier
	RuleName     string            // human-readable name
	Description  string            // context for LLM analysis
}

// ProbeSet groups probes by technology fingerprint.
type ProbeSet struct {
	Name      string   // set name (e.g. "spring-boot")
	TechMatch []string // httpx tech[] values that trigger this set (case-insensitive contains)
	Probes    []Probe
}

// AllProbeSets returns all registered probe sets.
func AllProbeSets() []ProbeSet {
	return []ProbeSet{
		genericProbes(),
		springBootProbes(),
		wordpressProbes(),
		nodeProbes(),
		laravelProbes(),
		djangoProbes(),
		dotnetProbes(),
		goProbes(),
	}
}

func genericProbes() ProbeSet {
	return ProbeSet{
		Name:      "generic",
		TechMatch: nil, // applies to all hosts
		Probes: []Probe{
			{
				Path: "/.env", ExpectStatus: []int{200},
				ExpectBody:  []string{"DB_", "APP_KEY", "SECRET", "PASSWORD", "API_KEY", "DATABASE_URL"},
				RejectBody:  []string{"<html", "<HTML", "<!DOCTYPE", "Page Not Found", "404"},
				Severity:    "critical",
				RuleID:      "generic-env-file",
				RuleName:    "Environment File Exposed",
				Description: ".env file containing secrets is publicly accessible",
			},
			{
				Path: "/.git/config", ExpectStatus: []int{200},
				ExpectBody:  []string{"[core]", "[remote"},
				RejectBody:  []string{"<html", "<HTML"},
				Severity:    "high",
				RuleID:      "generic-git-config",
				RuleName:    "Git Config Exposed",
				Description: ".git/config is accessible, full source code may be downloadable",
			},
			{
				Path: "/.git/HEAD", ExpectStatus: []int{200},
				ExpectBody:  []string{"ref: refs/"},
				RejectBody:  []string{"<html", "<HTML"},
				Severity:    "high",
				RuleID:      "generic-git-head",
				RuleName:    "Git HEAD Exposed",
				Description: ".git/HEAD is accessible, repository may be downloadable",
			},
			{
				Path: "/.DS_Store", ExpectStatus: []int{200},
				ExpectBody:  []string{"\x00\x00\x00\x01Bud1"},
				Severity:    "low",
				RuleID:      "generic-ds-store",
				RuleName:    "DS_Store File Exposed",
				Description: "macOS .DS_Store file leaks directory listing information",
			},
			{
				Path: "/server-status", ExpectStatus: []int{200},
				ExpectBody:  []string{"Apache Server Status"},
				RejectBody:  []string{"404", "Page Not Found"},
				Severity:    "medium",
				RuleID:      "generic-server-status",
				RuleName:    "Apache Server Status Exposed",
				Description: "Apache mod_status is publicly accessible, leaks request info",
			},
			{
				Path: "/server-info", ExpectStatus: []int{200},
				ExpectBody:  []string{"Apache Server Information"},
				RejectBody:  []string{"404", "Page Not Found"},
				Severity:    "medium",
				RuleID:      "generic-server-info",
				RuleName:    "Apache Server Info Exposed",
				Description: "Apache mod_info is publicly accessible, leaks server configuration",
			},
			{
				Path: "/.htaccess", ExpectStatus: []int{200},
				ExpectBody:  []string{"RewriteRule", "Deny", "Allow", "AuthType"},
				RejectBody:  []string{"<html", "<HTML"},
				Severity:    "medium",
				RuleID:      "generic-htaccess",
				RuleName:    "htaccess File Exposed",
				Description: ".htaccess file is publicly accessible, may reveal rewrite rules and auth config",
			},
			{
				Path: "/crossdomain.xml", ExpectStatus: []int{200},
				ExpectBody:  []string{`allow-access-from domain="*"`},
				Severity:    "medium",
				RuleID:      "generic-crossdomain-wildcard",
				RuleName:    "Crossdomain Wildcard Policy",
				Description: "crossdomain.xml allows access from any domain (Flash/Silverlight CSRF risk)",
			},
			{
				Path: "/robots.txt", ExpectStatus: []int{200},
				ExpectBody:  []string{"Disallow"},
				RejectBody:  []string{"<html", "<HTML"},
				Severity:    "info",
				RuleID:      "generic-robots-txt",
				RuleName:    "Robots.txt Found",
				Description: "robots.txt reveals hidden paths and directories",
			},
			{
				Path: "/sitemap.xml", ExpectStatus: []int{200},
				ExpectBody:  []string{"<urlset", "<sitemapindex"},
				Severity:    "info",
				RuleID:      "generic-sitemap",
				RuleName:    "Sitemap.xml Found",
				Description: "sitemap.xml reveals all indexed URLs",
			},
		},
	}
}

func springBootProbes() ProbeSet {
	return ProbeSet{
		Name:      "spring-boot",
		TechMatch: []string{"Spring", "Java"},
		Probes: []Probe{
			{
				Path: "/actuator", ExpectStatus: []int{200},
				ExpectBody:  []string{"_links"},
				RejectBody:  []string{"<html", "Page Not Found"},
				Severity:    "high",
				RuleID:      "spring-actuator-index",
				RuleName:    "Spring Actuator Index Exposed",
				Description: "Spring Boot Actuator index is accessible, all management endpoints may be exposed",
			},
			{
				Path: "/actuator/env", ExpectStatus: []int{200},
				ExpectBody:  []string{"propertySources", "activeProfiles"},
				Severity:    "critical",
				RuleID:      "spring-actuator-env",
				RuleName:    "Spring Actuator /env Exposed",
				Description: "Environment variables and properties exposed, may contain database credentials and API keys",
			},
			{
				Path: "/actuator/health", ExpectStatus: []int{200},
				ExpectBody:  []string{`"status"`},
				RejectBody:  []string{"<html"},
				Severity:    "info",
				RuleID:      "spring-actuator-health",
				RuleName:    "Spring Actuator /health Exposed",
				Description: "Health endpoint accessible, reveals component status and database connectivity",
			},
			{
				Path: "/actuator/configprops", ExpectStatus: []int{200},
				ExpectBody:  []string{"contexts", "beans"},
				Severity:    "high",
				RuleID:      "spring-actuator-configprops",
				RuleName:    "Spring Actuator /configprops Exposed",
				Description: "Configuration properties exposed, may contain sensitive values",
			},
			{
				Path: "/actuator/mappings", ExpectStatus: []int{200},
				ExpectBody:  []string{"dispatcherServlets", "handler"},
				Severity:    "medium",
				RuleID:      "spring-actuator-mappings",
				RuleName:    "Spring Actuator /mappings Exposed",
				Description: "URL mappings exposed, reveals all API endpoints and handlers",
			},
			{
				Path: "/actuator/beans", ExpectStatus: []int{200},
				ExpectBody:  []string{"contexts", "beans"},
				Severity:    "medium",
				RuleID:      "spring-actuator-beans",
				RuleName:    "Spring Actuator /beans Exposed",
				Description: "Spring beans exposed, reveals application architecture and dependencies",
			},
			{
				Path: "/actuator/heapdump", ExpectStatus: []int{200},
				ExpectBody:  nil, // binary; check Content-Length > 1MB in probe logic
				Severity:    "critical",
				RuleID:      "spring-actuator-heapdump",
				RuleName:    "Spring Actuator /heapdump Exposed",
				Description: "JVM heap dump downloadable, may contain credentials and session tokens in memory",
			},
			{
				Path: "/swagger-ui.html", ExpectStatus: []int{200},
				ExpectBody:  []string{"swagger"},
				Severity:    "info",
				RuleID:      "spring-swagger-ui",
				RuleName:    "Swagger UI Exposed",
				Description: "Swagger UI is accessible, reveals all API endpoints with parameters",
			},
			{
				Path: "/v2/api-docs", ExpectStatus: []int{200},
				ExpectBody:  []string{"swagger", "paths"},
				Severity:    "info",
				RuleID:      "spring-swagger-v2",
				RuleName:    "Swagger v2 API Docs Exposed",
				Description: "Swagger v2 API documentation is accessible",
			},
			{
				Path: "/v3/api-docs", ExpectStatus: []int{200},
				ExpectBody:  []string{"openapi", "paths"},
				Severity:    "info",
				RuleID:      "spring-openapi-v3",
				RuleName:    "OpenAPI v3 Docs Exposed",
				Description: "OpenAPI v3 documentation is accessible",
			},
		},
	}
}

func wordpressProbes() ProbeSet {
	return ProbeSet{
		Name:      "wordpress",
		TechMatch: []string{"WordPress", "WP Rocket"},
		Probes: []Probe{
			{
				Path: "/wp-config.php.bak", ExpectStatus: []int{200},
				ExpectBody:  []string{"DB_NAME", "DB_PASSWORD", "DB_HOST"},
				RejectBody:  []string{"<html", "<HTML"},
				Severity:    "critical",
				RuleID:      "wp-config-backup",
				RuleName:    "WordPress Config Backup Exposed",
				Description: "wp-config.php backup file exposes database credentials",
			},
			{
				Path: "/wp-config.php.old", ExpectStatus: []int{200},
				ExpectBody:  []string{"DB_NAME", "DB_PASSWORD"},
				RejectBody:  []string{"<html", "<HTML"},
				Severity:    "critical",
				RuleID:      "wp-config-old",
				RuleName:    "WordPress Config Old File Exposed",
				Description: "Old wp-config.php file exposes database credentials",
			},
			{
				Path: "/xmlrpc.php", ExpectStatus: []int{200, 405},
				ExpectBody:  []string{"XML-RPC server"},
				Severity:    "medium",
				RuleID:      "wp-xmlrpc",
				RuleName:    "WordPress XML-RPC Enabled",
				Description: "XML-RPC is enabled, can be used for brute-force and DDoS amplification",
			},
			{
				Path: "/wp-json/wp/v2/users", ExpectStatus: []int{200},
				ExpectBody:  []string{`"id"`, `"slug"`},
				RejectBody:  []string{"rest_no_route"},
				Severity:    "medium",
				RuleID:      "wp-user-enum",
				RuleName:    "WordPress User Enumeration via REST API",
				Description: "WordPress REST API exposes user list including usernames",
			},
			{
				Path: "/wp-content/debug.log", ExpectStatus: []int{200},
				ExpectBody:  []string{"PHP", "Stack trace", "Warning", "Error"},
				RejectBody:  []string{"<html", "<HTML"},
				Severity:    "high",
				RuleID:      "wp-debug-log",
				RuleName:    "WordPress Debug Log Exposed",
				Description: "Debug log file exposed, may contain errors with file paths and sensitive data",
			},
			{
				Path: "/wp-admin/install.php", ExpectStatus: []int{200},
				ExpectBody:  []string{"WordPress", "installation"},
				Severity:    "critical",
				RuleID:      "wp-install-exposed",
				RuleName:    "WordPress Installation Page Exposed",
				Description: "WordPress installation page is accessible, site may not be properly set up",
			},
		},
	}
}

func nodeProbes() ProbeSet {
	return ProbeSet{
		Name:      "nodejs",
		TechMatch: []string{"Express", "Node.js", "Next.js", "Nuxt"},
		Probes: []Probe{
			{
				Path: "/package.json", ExpectStatus: []int{200},
				ExpectBody:  []string{`"dependencies"`, `"name"`},
				RejectBody:  []string{"<html", "<HTML"},
				Severity:    "medium",
				RuleID:      "node-package-json",
				RuleName:    "package.json Exposed",
				Description: "package.json reveals dependencies and versions for targeted exploitation",
			},
			{
				Path: "/.npmrc", ExpectStatus: []int{200},
				ExpectBody:  []string{"registry", "//"},
				RejectBody:  []string{"<html", "<HTML"},
				Severity:    "high",
				RuleID:      "node-npmrc",
				RuleName:    ".npmrc Exposed",
				Description: ".npmrc may contain private registry tokens",
			},
			{
				Path: "/graphql", Method: "POST",
				Headers:      map[string]string{"Content-Type": "application/json"},
				Body:         `{"query":"{__schema{types{name}}}"}`,
				ExpectStatus: []int{200},
				ExpectBody:   []string{"__schema", "types"},
				Severity:     "medium",
				RuleID:       "node-graphql-introspection",
				RuleName:     "GraphQL Introspection Enabled",
				Description:  "GraphQL introspection is enabled, reveals entire API schema",
			},
			{
				Path: "/graphiql", ExpectStatus: []int{200},
				ExpectBody:  []string{"graphiql", "GraphiQL"},
				Severity:    "medium",
				RuleID:      "node-graphiql",
				RuleName:    "GraphiQL Interface Exposed",
				Description: "GraphiQL development interface is publicly accessible",
			},
		},
	}
}

func laravelProbes() ProbeSet {
	return ProbeSet{
		Name:      "laravel-php",
		TechMatch: []string{"Laravel", "PHP", "Symfony"},
		Probes: []Probe{
			{
				Path: "/storage/logs/laravel.log", ExpectStatus: []int{200},
				ExpectBody:  []string{"Stack trace", "Exception", "[stacktrace]"},
				RejectBody:  []string{"<html", "<HTML"},
				Severity:    "high",
				RuleID:      "laravel-log-exposed",
				RuleName:    "Laravel Log File Exposed",
				Description: "Laravel log file contains stack traces, file paths, and potentially sensitive data",
			},
			{
				Path: "/telescope", ExpectStatus: []int{200},
				ExpectBody:  []string{"Laravel Telescope", "telescope"},
				Severity:    "high",
				RuleID:      "laravel-telescope",
				RuleName:    "Laravel Telescope Exposed",
				Description: "Laravel Telescope debug dashboard is publicly accessible",
			},
			{
				Path: "/horizon", ExpectStatus: []int{200},
				ExpectBody:  []string{"Laravel Horizon", "horizon"},
				Severity:    "medium",
				RuleID:      "laravel-horizon",
				RuleName:    "Laravel Horizon Exposed",
				Description: "Laravel Horizon queue dashboard is publicly accessible",
			},
			{
				Path: "/phpinfo.php", ExpectStatus: []int{200},
				ExpectBody:  []string{"phpinfo()", "PHP Version", "PHP License"},
				Severity:    "medium",
				RuleID:      "php-phpinfo",
				RuleName:    "phpinfo() Exposed",
				Description: "phpinfo() page reveals PHP version, modules, and server configuration",
			},
			{
				Path: "/info.php", ExpectStatus: []int{200},
				ExpectBody:  []string{"phpinfo()", "PHP Version", "PHP License"},
				Severity:    "medium",
				RuleID:      "php-info-file",
				RuleName:    "PHP Info File Exposed",
				Description: "PHP info file reveals server configuration",
			},
		},
	}
}

func djangoProbes() ProbeSet {
	return ProbeSet{
		Name:      "django-python",
		TechMatch: []string{"Django", "Python", "Flask"},
		Probes: []Probe{
			{
				Path: "/admin/", ExpectStatus: []int{200},
				ExpectBody:  []string{"Django administration", "django", "Log in"},
				Severity:    "info",
				RuleID:      "django-admin",
				RuleName:    "Django Admin Panel Found",
				Description: "Django admin interface is accessible",
			},
			{
				Path: "/__debug__/", ExpectStatus: []int{200},
				ExpectBody:  []string{"djdt", "debug"},
				Severity:    "high",
				RuleID:      "django-debug-toolbar",
				RuleName:    "Django Debug Toolbar Exposed",
				Description: "Django Debug Toolbar is enabled in production, leaks SQL queries and request data",
			},
			{
				Path: "/api/swagger/", ExpectStatus: []int{200},
				ExpectBody:  []string{"swagger", "openapi"},
				Severity:    "info",
				RuleID:      "django-swagger",
				RuleName:    "Django Swagger API Docs Exposed",
				Description: "Swagger API documentation is publicly accessible",
			},
		},
	}
}

func dotnetProbes() ProbeSet {
	return ProbeSet{
		Name:      "dotnet",
		TechMatch: []string{"ASP.NET", "IIS", ".NET"},
		Probes: []Probe{
			{
				Path: "/elmah.axd", ExpectStatus: []int{200},
				ExpectBody:  []string{"Error Log", "ELMAH"},
				Severity:    "high",
				RuleID:      "dotnet-elmah",
				RuleName:    "ELMAH Error Log Exposed",
				Description: "ELMAH error log is publicly accessible, reveals exceptions and stack traces",
			},
			{
				Path: "/trace.axd", ExpectStatus: []int{200},
				ExpectBody:  []string{"Application Trace", "Request Details"},
				Severity:    "high",
				RuleID:      "dotnet-trace",
				RuleName:    "ASP.NET Trace Exposed",
				Description: "ASP.NET trace is publicly accessible, reveals request details and server variables",
			},
			{
				Path: "/web.config", ExpectStatus: []int{200},
				ExpectBody:  []string{"<configuration", "connectionStrings", "appSettings"},
				RejectBody:  []string{"<html", "<HTML"},
				Severity:    "critical",
				RuleID:      "dotnet-web-config",
				RuleName:    "web.config Exposed",
				Description: "web.config file exposes connection strings, API keys, and application settings",
			},
			{
				Path: "/appsettings.json", ExpectStatus: []int{200},
				ExpectBody:  []string{"ConnectionStrings", "Logging", "AllowedHosts"},
				RejectBody:  []string{"<html", "<HTML"},
				Severity:    "critical",
				RuleID:      "dotnet-appsettings",
				RuleName:    "appsettings.json Exposed",
				Description: "appsettings.json exposes connection strings and application configuration",
			},
			{
				Path: "/swagger/index.html", ExpectStatus: []int{200},
				ExpectBody:  []string{"swagger", "Swagger"},
				Severity:    "info",
				RuleID:      "dotnet-swagger",
				RuleName:    "Swagger UI Exposed (.NET)",
				Description: "Swagger UI is publicly accessible",
			},
		},
	}
}

func goProbes() ProbeSet {
	return ProbeSet{
		Name:      "go-pprof",
		TechMatch: []string{"Go"},
		Probes: []Probe{
			{
				Path: "/debug/pprof/", ExpectStatus: []int{200},
				ExpectBody:  []string{"Types of profiles available", "goroutine", "heap"},
				RejectBody:  []string{"<html", "Page Not Found"},
				Severity:    "high",
				RuleID:      "go-pprof-index",
				RuleName:    "Go pprof Debug Index Exposed",
				Description: "Go net/http/pprof is enabled in production, exposes profiling data and heap dumps",
			},
			{
				Path: "/debug/pprof/heap", ExpectStatus: []int{200},
				ExpectBody:  nil, // binary profile data
				Severity:    "critical",
				RuleID:      "go-pprof-heap",
				RuleName:    "Go pprof Heap Dump Exposed",
				Description: "Heap profile downloadable, may contain credentials and sensitive data in memory",
			},
			{
				Path: "/debug/pprof/goroutine?debug=1", ExpectStatus: []int{200},
				ExpectBody:  []string{"goroutine", "runtime"},
				Severity:    "high",
				RuleID:      "go-pprof-goroutine",
				RuleName:    "Go pprof Goroutine Dump Exposed",
				Description: "Goroutine stack dump exposes internal code paths and function names",
			},
			{
				Path: "/debug/pprof/cmdline", ExpectStatus: []int{200},
				ExpectBody:  nil, // returns command line, any non-empty response is a hit
				Severity:    "high",
				RuleID:      "go-pprof-cmdline",
				RuleName:    "Go pprof Cmdline Exposed",
				Description: "Command line arguments exposed, may contain secrets passed via flags",
			},
			{
				Path: "/debug/vars", ExpectStatus: []int{200},
				ExpectBody:  []string{"cmdline", "memstats"},
				RejectBody:  []string{"<html"},
				Severity:    "medium",
				RuleID:      "go-expvar",
				RuleName:    "Go expvar Debug Variables Exposed",
				Description: "Go expvar endpoint exposes all exported application variables as JSON",
			},
		},
	}
}
