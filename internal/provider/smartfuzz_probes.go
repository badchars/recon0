package provider

// FuzzProbe defines a single HTTP probe.
type FuzzProbe struct {
	Path         string
	Method       string            // default: GET
	Headers      map[string]string
	Body         string
	ExpectStatus []int
	ExpectBody   []string
	RejectBody   []string
	Severity     string
	RuleID       string
	RuleName     string
	Description  string
	Universal    bool   // if true, sent to ALL hosts regardless of tech
	TechDiscover string // if response matches, mark host as this tech (runtime discovery)
}

// FuzzProbeSet groups probes by technology fingerprint.
type FuzzProbeSet struct {
	Name      string
	TechMatch []string // httpx tech values that trigger this set (case-insensitive contains)
	Probes    []FuzzProbe
}

// prefixEntry marks whether a prefix was discovered from pipeline data or hardcoded.
type prefixEntry struct {
	Path       string
	Discovered bool // true = from crawl/discover data, false = hardcoded fallback
}

// defaultPrefixes are generic hardcoded prefixes used as fallback.
var defaultPrefixes = []string{
	"/manage",
	"/admin",
	"/api",
	"/api/v1",
	"/api/v2",
	"/v1",
	"/v2",
	"/internal",
	"/system",
	"/portal",
}

// mergePrefixes combines discovered (evidence-based) and hardcoded (fallback) prefixes.
// Discovered prefixes come first since they have higher signal.
func mergePrefixes(discovered []string, hardcoded []string) []prefixEntry {
	seen := make(map[string]bool)
	var merged []prefixEntry

	// Discovered prefixes first — evidence-based, higher priority
	for _, p := range discovered {
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		merged = append(merged, prefixEntry{Path: p, Discovered: true})
	}

	// Hardcoded fallback — generic common paths
	for _, p := range hardcoded {
		if p == "" || seen[p] {
			continue
		}
		seen[p] = true
		merged = append(merged, prefixEntry{Path: p, Discovered: false})
	}

	return merged
}

// AllFuzzProbeSets returns all registered probe sets.
func AllFuzzProbeSets() []FuzzProbeSet {
	return []FuzzProbeSet{
		universalProbes(),
		springBootFuzzProbes(),
		swaggerProbes(),
		phpmyadminProbes(),
		wordpressFuzzProbes(),
		nodeFuzzProbes(),
		laravelFuzzProbes(),
		djangoFuzzProbes(),
		dotnetFuzzProbes(),
		goFuzzProbes(),
		aiLLMProbes(),
		vectorDBProbes(),
		quarkusFuzzProbes(),
		micronautFuzzProbes(),
		devopsFuzzProbes(),
		configFileProbes(),
		modernJSFuzzProbes(),
	}
}

// ExpandWithPrefixes generates path variations for a probe using given prefixes.
// The original path (no prefix) is always included first.
func ExpandWithPrefixes(probe FuzzProbe, prefixes []prefixEntry) []FuzzProbe {
	var expanded []FuzzProbe
	seen := make(map[string]bool)

	// Always include the original path first (no prefix)
	expanded = append(expanded, probe)
	seen[probe.Path] = true

	for _, prefix := range prefixes {
		if prefix.Path == "" {
			continue
		}
		newPath := prefix.Path + probe.Path
		if seen[newPath] {
			continue
		}
		seen[newPath] = true

		p := probe
		p.Path = newPath
		if prefix.Discovered {
			p.RuleID = probe.RuleID + "-dprefix"
		} else {
			p.RuleID = probe.RuleID + "-prefix"
		}
		expanded = append(expanded, p)
	}
	return expanded
}

// ── Universal Probes: sent to EVERY host, no tech detection required ──

func universalProbes() FuzzProbeSet {
	return FuzzProbeSet{
		Name:      "universal",
		TechMatch: nil,
		Probes: []FuzzProbe{
			// Config/secret leaks
			{
				Path: "/.env", ExpectStatus: []int{200},
				ExpectBody: []string{"DB_", "APP_KEY", "SECRET", "PASSWORD", "API_KEY", "DATABASE_URL"},
				RejectBody: []string{"<html", "<HTML", "<!DOCTYPE", "Page Not Found", "404"},
				Severity: "critical", RuleID: "generic-env-file",
				RuleName: "Environment File Exposed", Universal: true,
				Description: ".env file containing secrets is publicly accessible",
			},
			{
				Path: "/.git/HEAD", ExpectStatus: []int{200},
				ExpectBody: []string{"ref: refs/"}, RejectBody: []string{"<html", "<HTML"},
				Severity: "high", RuleID: "generic-git-head",
				RuleName: "Git HEAD Exposed", Universal: true,
				Description: ".git/HEAD is accessible, repository may be downloadable",
			},
			{
				Path: "/.git/config", ExpectStatus: []int{200},
				ExpectBody: []string{"[core]", "[remote"}, RejectBody: []string{"<html", "<HTML"},
				Severity: "high", RuleID: "generic-git-config",
				RuleName: "Git Config Exposed", Universal: true,
				Description: ".git/config is accessible, full source code may be downloadable",
			},
			// Tech discovery probes — trigger full tech-specific scanning
			{
				Path: "/actuator/health", ExpectStatus: []int{200},
				ExpectBody: []string{`"status"`}, RejectBody: []string{"<html"},
				Severity: "info", RuleID: "spring-actuator-health",
				RuleName: "Spring Actuator /health Exposed", Universal: true,
				Description:  "Health endpoint accessible, reveals component status",
				TechDiscover: "Spring",
			},
			{
				Path: "/wp-login.php", ExpectStatus: []int{200},
				ExpectBody: []string{"wp-submit", "WordPress"},
				Severity: "info", RuleID: "wp-login-found",
				RuleName: "WordPress Login Found", Universal: true,
				Description:  "WordPress login page detected",
				TechDiscover: "WordPress",
			},
			{
				Path: "/debug/pprof/", ExpectStatus: []int{200},
				ExpectBody: []string{"Types of profiles available", "goroutine", "heap"},
				RejectBody: []string{"Page Not Found"},
				Severity: "high", RuleID: "go-pprof-index",
				RuleName: "Go pprof Debug Index Exposed", Universal: true,
				Description:  "Go net/http/pprof is enabled in production",
				TechDiscover: "Go",
			},
			{
				Path: "/phpinfo.php", ExpectStatus: []int{200},
				ExpectBody: []string{"phpinfo()", "PHP Version"},
				Severity: "medium", RuleID: "php-phpinfo",
				RuleName: "phpinfo() Exposed", Universal: true,
				Description:  "phpinfo() page reveals PHP configuration",
				TechDiscover: "PHP",
			},
			// Swagger/OpenAPI discovery
			{
				Path: "/swagger.json", ExpectStatus: []int{200},
				ExpectBody: []string{"swagger", "paths"},
				Severity: "info", RuleID: "swagger-json",
				RuleName: "Swagger JSON Exposed", Universal: true,
				Description: "Swagger API documentation is publicly accessible",
			},
			{
				Path: "/openapi.json", ExpectStatus: []int{200},
				ExpectBody: []string{"openapi", "paths"},
				Severity: "info", RuleID: "openapi-json",
				RuleName: "OpenAPI JSON Exposed", Universal: true,
				Description: "OpenAPI documentation is publicly accessible",
			},
			{
				Path: "/v2/api-docs", ExpectStatus: []int{200},
				ExpectBody: []string{"swagger", "paths"},
				Severity: "info", RuleID: "swagger-v2-api-docs",
				RuleName: "Swagger v2 API Docs Exposed", Universal: true,
				Description: "Swagger v2 API documentation is accessible",
			},
			{
				Path: "/v3/api-docs", ExpectStatus: []int{200},
				ExpectBody: []string{"openapi", "paths"},
				Severity: "info", RuleID: "openapi-v3-api-docs",
				RuleName: "OpenAPI v3 Docs Exposed", Universal: true,
				Description: "OpenAPI v3 documentation is accessible",
			},
			{
				Path: "/graphql", Method: "POST",
				Headers:      map[string]string{"Content-Type": "application/json"},
				Body:         `{"query":"{__schema{types{name}}}"}`,
				ExpectStatus: []int{200},
				ExpectBody:   []string{"__schema", "types"},
				Severity: "medium", RuleID: "graphql-introspection",
				RuleName: "GraphQL Introspection Enabled", Universal: true,
				Description: "GraphQL introspection is enabled, reveals entire API schema",
			},
			// Apache info
			{
				Path: "/server-status", ExpectStatus: []int{200},
				ExpectBody: []string{"Apache Server Status"},
				RejectBody: []string{"404", "Page Not Found"},
				Severity: "medium", RuleID: "generic-server-status",
				RuleName: "Apache Server Status Exposed", Universal: true,
				Description: "Apache mod_status is publicly accessible",
			},
			// Misc
			{
				Path: "/.DS_Store", ExpectStatus: []int{200},
				ExpectBody: []string{"\x00\x00\x00\x01Bud1"},
				Severity: "low", RuleID: "generic-ds-store",
				RuleName: "DS_Store File Exposed", Universal: true,
				Description: "macOS .DS_Store file leaks directory listing information",
			},
			{
				Path: "/.htaccess", ExpectStatus: []int{200},
				ExpectBody: []string{"RewriteRule", "Deny", "Allow", "AuthType"},
				RejectBody: []string{"<html", "<HTML"},
				Severity: "medium", RuleID: "generic-htaccess",
				RuleName: "htaccess File Exposed", Universal: true,
				Description: ".htaccess file reveals rewrite rules and auth config",
			},
			{
				Path: "/robots.txt", ExpectStatus: []int{200},
				ExpectBody: []string{"Disallow"}, RejectBody: []string{"<html", "<HTML"},
				Severity: "info", RuleID: "generic-robots-txt",
				RuleName: "Robots.txt Found", Universal: true,
				Description: "robots.txt reveals hidden paths and directories",
			},
			{
				Path: "/crossdomain.xml", ExpectStatus: []int{200},
				ExpectBody: []string{`allow-access-from domain="*"`},
				Severity: "medium", RuleID: "generic-crossdomain-wildcard",
				RuleName: "Crossdomain Wildcard Policy", Universal: true,
				Description: "crossdomain.xml allows access from any domain",
			},
			{
				Path: "/sitemap.xml", ExpectStatus: []int{200},
				ExpectBody: []string{"<urlset", "<sitemapindex"},
				Severity: "info", RuleID: "generic-sitemap",
				RuleName: "Sitemap.xml Found", Universal: true,
				Description: "sitemap.xml reveals all indexed URLs",
			},
			{
				Path: "/.well-known/security.txt", ExpectStatus: []int{200},
				ExpectBody: []string{"Contact"},
				Severity: "info", RuleID: "generic-security-txt",
				RuleName: "security.txt Found", Universal: true,
				Description: "security.txt reveals security contact information",
			},
			{
				Path: "/server-info", ExpectStatus: []int{200},
				ExpectBody: []string{"Apache Server Information"},
				RejectBody: []string{"404", "Page Not Found"},
				Severity: "medium", RuleID: "generic-server-info",
				RuleName: "Apache Server Info Exposed", Universal: true,
				Description: "Apache mod_info is publicly accessible",
			},
		},
	}
}

// ── Spring Boot (TechMatch + runtime discovery via /actuator/health) ──

func springBootFuzzProbes() FuzzProbeSet {
	return FuzzProbeSet{
		Name:      "spring-boot",
		TechMatch: []string{"Spring", "Java"},
		Probes: []FuzzProbe{
			{Path: "/actuator", ExpectStatus: []int{200}, ExpectBody: []string{"_links"}, RejectBody: []string{"<html", "Page Not Found"}, Severity: "high", RuleID: "spring-actuator-index", RuleName: "Spring Actuator Index Exposed", Description: "Spring Boot Actuator index accessible"},
			{Path: "/actuator/env", ExpectStatus: []int{200}, ExpectBody: []string{"propertySources", "activeProfiles"}, Severity: "critical", RuleID: "spring-actuator-env", RuleName: "Spring Actuator /env Exposed", Description: "Environment variables exposed, may contain credentials"},
			{Path: "/actuator/configprops", ExpectStatus: []int{200}, ExpectBody: []string{"contexts", "beans"}, Severity: "high", RuleID: "spring-actuator-configprops", RuleName: "Spring Actuator /configprops Exposed", Description: "Configuration properties exposed"},
			{Path: "/actuator/mappings", ExpectStatus: []int{200}, ExpectBody: []string{"dispatcherServlets", "handler"}, Severity: "medium", RuleID: "spring-actuator-mappings", RuleName: "Spring Actuator /mappings Exposed", Description: "URL mappings reveal all API endpoints"},
			{Path: "/actuator/beans", ExpectStatus: []int{200}, ExpectBody: []string{"contexts", "beans"}, Severity: "medium", RuleID: "spring-actuator-beans", RuleName: "Spring Actuator /beans Exposed", Description: "Spring beans exposed"},
			{Path: "/actuator/heapdump", ExpectStatus: []int{200}, Severity: "critical", RuleID: "spring-actuator-heapdump", RuleName: "Spring Actuator /heapdump Exposed", Description: "JVM heap dump downloadable"},
			{Path: "/actuator/threaddump", ExpectStatus: []int{200}, ExpectBody: []string{"threads", "threadName"}, Severity: "high", RuleID: "spring-actuator-threaddump", RuleName: "Spring Actuator /threaddump Exposed", Description: "Thread dump exposes internal code execution"},
			{Path: "/actuator/metrics", ExpectStatus: []int{200}, ExpectBody: []string{"names"}, RejectBody: []string{"<html"}, Severity: "medium", RuleID: "spring-actuator-metrics", RuleName: "Spring Actuator /metrics Exposed", Description: "Application metrics exposed"},
			{Path: "/actuator/caches", ExpectStatus: []int{200}, ExpectBody: []string{"cacheManagers"}, Severity: "medium", RuleID: "spring-actuator-caches", RuleName: "Spring Actuator /caches Exposed", Description: "Cache information exposed"},
			{Path: "/actuator/scheduledtasks", ExpectStatus: []int{200}, ExpectBody: []string{"cron", "fixedRate"}, Severity: "medium", RuleID: "spring-actuator-tasks", RuleName: "Spring Actuator /scheduledtasks Exposed", Description: "Scheduled tasks exposed"},
			{Path: "/actuator/httptrace", ExpectStatus: []int{200}, ExpectBody: []string{"traces", "request"}, Severity: "high", RuleID: "spring-actuator-httptrace", RuleName: "Spring Actuator /httptrace Exposed", Description: "HTTP trace exposes recent requests including headers"},
			{Path: "/actuator/loggers", ExpectStatus: []int{200}, ExpectBody: []string{"levels", "loggers"}, Severity: "medium", RuleID: "spring-actuator-loggers", RuleName: "Spring Actuator /loggers Exposed", Description: "Logger configuration exposed and modifiable"},
			{Path: "/actuator/prometheus", ExpectStatus: []int{200}, ExpectBody: []string{"jvm_", "http_server"}, Severity: "medium", RuleID: "spring-actuator-prometheus", RuleName: "Spring Actuator /prometheus Exposed", Description: "Prometheus metrics endpoint exposed"},
			{Path: "/actuator/jolokia", ExpectStatus: []int{200}, ExpectBody: []string{"agent", "jolokia"}, Severity: "critical", RuleID: "spring-actuator-jolokia", RuleName: "Spring Actuator /jolokia Exposed", Description: "Jolokia JMX bridge exposed — potential RCE"},
			{Path: "/actuator/flyway", ExpectStatus: []int{200}, ExpectBody: []string{"flywayBeans"}, Severity: "medium", RuleID: "spring-actuator-flyway", RuleName: "Spring Actuator /flyway Exposed", Description: "Database migration info exposed"},
			{Path: "/h2-console", ExpectStatus: []int{200}, ExpectBody: []string{"H2 Console", "h2-console"}, Severity: "critical", RuleID: "spring-h2-console", RuleName: "H2 Database Console Exposed", Description: "H2 in-memory database console is accessible — potential RCE"},
		},
	}
}

// ── Swagger/OpenAPI (expanded paths) ──

func swaggerProbes() FuzzProbeSet {
	return FuzzProbeSet{
		Name:      "swagger-openapi",
		TechMatch: nil, // universal but expanded beyond the basic universal set
		Probes: []FuzzProbe{
			{Path: "/swagger.yaml", ExpectStatus: []int{200}, ExpectBody: []string{"swagger", "paths"}, Severity: "info", RuleID: "swagger-yaml", RuleName: "Swagger YAML Exposed", Description: "Swagger YAML is accessible", Universal: true},
			{Path: "/openapi.yaml", ExpectStatus: []int{200}, ExpectBody: []string{"openapi", "paths"}, Severity: "info", RuleID: "openapi-yaml", RuleName: "OpenAPI YAML Exposed", Description: "OpenAPI YAML is accessible", Universal: true},
			{Path: "/swagger-ui.html", ExpectStatus: []int{200}, ExpectBody: []string{"swagger"}, Severity: "info", RuleID: "swagger-ui-html", RuleName: "Swagger UI Exposed", Description: "Swagger UI is publicly accessible", Universal: true},
			{Path: "/swagger-ui/", ExpectStatus: []int{200}, ExpectBody: []string{"swagger"}, Severity: "info", RuleID: "swagger-ui-dir", RuleName: "Swagger UI Directory Exposed", Description: "Swagger UI directory is accessible", Universal: true},
			{Path: "/swagger-ui/index.html", ExpectStatus: []int{200}, ExpectBody: []string{"swagger"}, Severity: "info", RuleID: "swagger-ui-index", RuleName: "Swagger UI Index Exposed", Description: "Swagger UI index is accessible", Universal: true},
			{Path: "/swagger-resources", ExpectStatus: []int{200}, ExpectBody: []string{"url", "swagger"}, Severity: "info", RuleID: "swagger-resources", RuleName: "Swagger Resources Exposed", Description: "Swagger resource listing is accessible", Universal: true},
			{Path: "/api-docs", ExpectStatus: []int{200}, ExpectBody: []string{"paths", "info"}, Severity: "info", RuleID: "api-docs-generic", RuleName: "API Docs Exposed", Description: "API documentation is accessible", Universal: true},
			{Path: "/api-docs.json", ExpectStatus: []int{200}, ExpectBody: []string{"paths", "info"}, Severity: "info", RuleID: "api-docs-json", RuleName: "API Docs JSON Exposed", Description: "API JSON documentation is accessible", Universal: true},
			{Path: "/api-docs.yaml", ExpectStatus: []int{200}, ExpectBody: []string{"paths", "info"}, Severity: "info", RuleID: "api-docs-yaml", RuleName: "API Docs YAML Exposed", Description: "API YAML documentation is accessible", Universal: true},
			{Path: "/redoc", ExpectStatus: []int{200}, ExpectBody: []string{"redoc", "ReDoc"}, Severity: "info", RuleID: "redoc", RuleName: "ReDoc API Docs Exposed", Description: "ReDoc API documentation is accessible", Universal: true},
			{Path: "/docs", ExpectStatus: []int{200}, ExpectBody: []string{"swagger", "openapi", "api"}, Severity: "info", RuleID: "docs-generic", RuleName: "API Documentation Found", Description: "Documentation endpoint is accessible", Universal: true},
			{Path: "/api/docs", ExpectStatus: []int{200}, ExpectBody: []string{"swagger", "openapi", "api"}, Severity: "info", RuleID: "api-docs-path", RuleName: "API Documentation Found", Description: "API documentation endpoint is accessible", Universal: true},
		},
	}
}

// ── phpMyAdmin ──

func phpmyadminProbes() FuzzProbeSet {
	return FuzzProbeSet{
		Name:      "phpmyadmin",
		TechMatch: []string{"PHP", "MySQL", "MariaDB"},
		Probes: []FuzzProbe{
			{Path: "/phpmyadmin/", ExpectStatus: []int{200, 401, 403}, ExpectBody: []string{"phpMyAdmin", "pma_", "pmahomme"}, Severity: "high", RuleID: "pma-default", RuleName: "phpMyAdmin Found", Description: "phpMyAdmin is accessible"},
			{Path: "/pma/", ExpectStatus: []int{200, 401, 403}, ExpectBody: []string{"phpMyAdmin", "pma_"}, Severity: "high", RuleID: "pma-short", RuleName: "phpMyAdmin (pma) Found", Description: "phpMyAdmin at /pma/"},
			{Path: "/myadmin/", ExpectStatus: []int{200, 401, 403}, ExpectBody: []string{"phpMyAdmin", "pma_"}, Severity: "high", RuleID: "pma-myadmin", RuleName: "phpMyAdmin (myadmin) Found", Description: "phpMyAdmin at /myadmin/"},
			{Path: "/phpMyAdmin/", ExpectStatus: []int{200, 401, 403}, ExpectBody: []string{"phpMyAdmin", "pma_"}, Severity: "high", RuleID: "pma-camel", RuleName: "phpMyAdmin (CamelCase) Found", Description: "phpMyAdmin at /phpMyAdmin/"},
			{Path: "/dbadmin/", ExpectStatus: []int{200, 401, 403}, ExpectBody: []string{"phpMyAdmin", "pma_"}, Severity: "high", RuleID: "pma-dbadmin", RuleName: "phpMyAdmin (dbadmin) Found", Description: "phpMyAdmin at /dbadmin/"},
			{Path: "/mysql/", ExpectStatus: []int{200, 401, 403}, ExpectBody: []string{"phpMyAdmin", "pma_"}, Severity: "high", RuleID: "pma-mysql", RuleName: "phpMyAdmin (mysql) Found", Description: "phpMyAdmin at /mysql/"},
			{Path: "/mysqladmin/", ExpectStatus: []int{200, 401, 403}, ExpectBody: []string{"phpMyAdmin", "pma_"}, Severity: "high", RuleID: "pma-mysqladmin", RuleName: "phpMyAdmin (mysqladmin) Found", Description: "phpMyAdmin at /mysqladmin/"},
			{Path: "/sql/", ExpectStatus: []int{200, 401, 403}, ExpectBody: []string{"phpMyAdmin", "pma_"}, Severity: "high", RuleID: "pma-sql", RuleName: "phpMyAdmin (sql) Found", Description: "phpMyAdmin at /sql/"},
			{Path: "/db/", ExpectStatus: []int{200, 401, 403}, ExpectBody: []string{"phpMyAdmin", "pma_", "Adminer"}, Severity: "high", RuleID: "pma-db", RuleName: "Database Admin Found", Description: "Database admin panel at /db/"},
			{Path: "/adminer.php", ExpectStatus: []int{200}, ExpectBody: []string{"Adminer", "adminer"}, Severity: "high", RuleID: "adminer", RuleName: "Adminer Found", Description: "Adminer database management tool is accessible"},
		},
	}
}

// ── WordPress ──

func wordpressFuzzProbes() FuzzProbeSet {
	return FuzzProbeSet{
		Name:      "wordpress",
		TechMatch: []string{"WordPress", "WP Rocket"},
		Probes: []FuzzProbe{
			{Path: "/wp-config.php.bak", ExpectStatus: []int{200}, ExpectBody: []string{"DB_NAME", "DB_PASSWORD"}, RejectBody: []string{"<html"}, Severity: "critical", RuleID: "wp-config-backup", RuleName: "WordPress Config Backup Exposed", Description: "wp-config.php backup exposes database credentials"},
			{Path: "/wp-config.php.old", ExpectStatus: []int{200}, ExpectBody: []string{"DB_NAME", "DB_PASSWORD"}, RejectBody: []string{"<html"}, Severity: "critical", RuleID: "wp-config-old", RuleName: "WordPress Config Old File Exposed", Description: "Old wp-config.php exposes credentials"},
			{Path: "/wp-config.php~", ExpectStatus: []int{200}, ExpectBody: []string{"DB_NAME", "DB_PASSWORD"}, RejectBody: []string{"<html"}, Severity: "critical", RuleID: "wp-config-tilde", RuleName: "WordPress Config Backup (~) Exposed", Description: "Editor backup of wp-config.php"},
			{Path: "/wp-config.php.save", ExpectStatus: []int{200}, ExpectBody: []string{"DB_NAME", "DB_PASSWORD"}, RejectBody: []string{"<html"}, Severity: "critical", RuleID: "wp-config-save", RuleName: "WordPress Config Save File Exposed", Description: "Editor save of wp-config.php"},
			{Path: "/xmlrpc.php", ExpectStatus: []int{200, 405}, ExpectBody: []string{"XML-RPC server"}, Severity: "medium", RuleID: "wp-xmlrpc", RuleName: "WordPress XML-RPC Enabled", Description: "XML-RPC can be used for brute-force"},
			{Path: "/wp-json/wp/v2/users", ExpectStatus: []int{200}, ExpectBody: []string{`"id"`, `"slug"`}, RejectBody: []string{"rest_no_route"}, Severity: "medium", RuleID: "wp-user-enum", RuleName: "WordPress User Enumeration", Description: "REST API exposes user list"},
			{Path: "/wp-content/debug.log", ExpectStatus: []int{200}, ExpectBody: []string{"PHP", "Stack trace", "Warning", "Error"}, RejectBody: []string{"<html"}, Severity: "high", RuleID: "wp-debug-log", RuleName: "WordPress Debug Log Exposed", Description: "Debug log with sensitive data"},
			{Path: "/wp-admin/install.php", ExpectStatus: []int{200}, ExpectBody: []string{"WordPress", "installation"}, Severity: "critical", RuleID: "wp-install-exposed", RuleName: "WordPress Installation Page Exposed", Description: "WordPress not properly installed"},
			{Path: "/wp-content/uploads/", ExpectStatus: []int{200}, ExpectBody: []string{"Index of", "Parent Directory"}, Severity: "medium", RuleID: "wp-uploads-listing", RuleName: "WordPress Uploads Directory Listing", Description: "Uploads directory listing enabled"},
			{Path: "/wp-includes/", ExpectStatus: []int{200}, ExpectBody: []string{"Index of", "Parent Directory"}, Severity: "low", RuleID: "wp-includes-listing", RuleName: "WordPress Includes Directory Listing", Description: "Includes directory listing enabled"},
		},
	}
}

// ── Node.js / Express ──

func nodeFuzzProbes() FuzzProbeSet {
	return FuzzProbeSet{
		Name:      "nodejs",
		TechMatch: []string{"Express", "Node.js", "Next.js", "Nuxt"},
		Probes: []FuzzProbe{
			{Path: "/package.json", ExpectStatus: []int{200}, ExpectBody: []string{`"dependencies"`, `"name"`}, RejectBody: []string{"<html"}, Severity: "medium", RuleID: "node-package-json", RuleName: "package.json Exposed", Description: "Dependencies and versions exposed"},
			{Path: "/.npmrc", ExpectStatus: []int{200}, ExpectBody: []string{"registry", "//"}, RejectBody: []string{"<html"}, Severity: "high", RuleID: "node-npmrc", RuleName: ".npmrc Exposed", Description: ".npmrc may contain private registry tokens"},
			{Path: "/graphiql", ExpectStatus: []int{200}, ExpectBody: []string{"graphiql", "GraphiQL"}, Severity: "medium", RuleID: "node-graphiql", RuleName: "GraphiQL Interface Exposed", Description: "GraphiQL development interface is accessible"},
			{Path: "/.next/BUILD_ID", ExpectStatus: []int{200}, RejectBody: []string{"<html"}, Severity: "low", RuleID: "nextjs-build-id", RuleName: "Next.js Build ID Exposed", Description: "Next.js build identifier exposed"},
		},
	}
}

// ── Laravel / PHP ──

func laravelFuzzProbes() FuzzProbeSet {
	return FuzzProbeSet{
		Name:      "laravel-php",
		TechMatch: []string{"Laravel", "PHP", "Symfony"},
		Probes: []FuzzProbe{
			{Path: "/storage/logs/laravel.log", ExpectStatus: []int{200}, ExpectBody: []string{"Stack trace", "Exception", "[stacktrace]"}, RejectBody: []string{"<html"}, Severity: "high", RuleID: "laravel-log-exposed", RuleName: "Laravel Log File Exposed", Description: "Laravel log with stack traces"},
			{Path: "/telescope", ExpectStatus: []int{200}, ExpectBody: []string{"Laravel Telescope", "telescope"}, Severity: "high", RuleID: "laravel-telescope", RuleName: "Laravel Telescope Exposed", Description: "Debug dashboard is publicly accessible"},
			{Path: "/horizon", ExpectStatus: []int{200}, ExpectBody: []string{"Laravel Horizon", "horizon"}, Severity: "medium", RuleID: "laravel-horizon", RuleName: "Laravel Horizon Exposed", Description: "Queue dashboard is accessible"},
			{Path: "/_debugbar/open", ExpectStatus: []int{200}, ExpectBody: []string{"debugbar"}, Severity: "high", RuleID: "laravel-debugbar", RuleName: "Laravel Debugbar Exposed", Description: "Debug bar exposes SQL queries and request data"},
			{Path: "/info.php", ExpectStatus: []int{200}, ExpectBody: []string{"phpinfo()", "PHP Version"}, Severity: "medium", RuleID: "php-info-file", RuleName: "PHP Info File Exposed", Description: "PHP info reveals server configuration"},
		},
	}
}

// ── Django / Python ──

func djangoFuzzProbes() FuzzProbeSet {
	return FuzzProbeSet{
		Name:      "django-python",
		TechMatch: []string{"Django", "Python", "Flask"},
		Probes: []FuzzProbe{
			{Path: "/admin/", ExpectStatus: []int{200}, ExpectBody: []string{"Django administration", "django", "Log in"}, Severity: "info", RuleID: "django-admin", RuleName: "Django Admin Panel Found", Description: "Django admin interface is accessible"},
			{Path: "/__debug__/", ExpectStatus: []int{200}, ExpectBody: []string{"djdt", "debug"}, Severity: "high", RuleID: "django-debug-toolbar", RuleName: "Django Debug Toolbar Exposed", Description: "Debug toolbar leaks SQL queries"},
			{Path: "/api/swagger/", ExpectStatus: []int{200}, ExpectBody: []string{"swagger", "openapi"}, Severity: "info", RuleID: "django-swagger", RuleName: "Django Swagger Exposed", Description: "Swagger docs accessible"},
			{Path: "/settings.py", ExpectStatus: []int{200}, ExpectBody: []string{"SECRET_KEY", "DATABASES"}, RejectBody: []string{"<html"}, Severity: "critical", RuleID: "django-settings", RuleName: "Django Settings Exposed", Description: "Django settings.py with SECRET_KEY exposed"},
		},
	}
}

// ── .NET ──

func dotnetFuzzProbes() FuzzProbeSet {
	return FuzzProbeSet{
		Name:      "dotnet",
		TechMatch: []string{"ASP.NET", "IIS", ".NET"},
		Probes: []FuzzProbe{
			{Path: "/elmah.axd", ExpectStatus: []int{200}, ExpectBody: []string{"Error Log", "ELMAH"}, Severity: "high", RuleID: "dotnet-elmah", RuleName: "ELMAH Error Log Exposed", Description: "Error log reveals exceptions"},
			{Path: "/trace.axd", ExpectStatus: []int{200}, ExpectBody: []string{"Application Trace", "Request Details"}, Severity: "high", RuleID: "dotnet-trace", RuleName: "ASP.NET Trace Exposed", Description: "Request trace reveals server variables"},
			{Path: "/web.config", ExpectStatus: []int{200}, ExpectBody: []string{"<configuration", "connectionStrings"}, RejectBody: []string{"<html"}, Severity: "critical", RuleID: "dotnet-web-config", RuleName: "web.config Exposed", Description: "Connection strings and settings exposed"},
			{Path: "/appsettings.json", ExpectStatus: []int{200}, ExpectBody: []string{"ConnectionStrings", "Logging"}, RejectBody: []string{"<html"}, Severity: "critical", RuleID: "dotnet-appsettings", RuleName: "appsettings.json Exposed", Description: "Application configuration exposed"},
			{Path: "/appsettings.Development.json", ExpectStatus: []int{200}, ExpectBody: []string{"ConnectionStrings", "Logging"}, RejectBody: []string{"<html"}, Severity: "critical", RuleID: "dotnet-appsettings-dev", RuleName: "appsettings.Development.json Exposed", Description: "Development configuration exposed"},
			{Path: "/swagger/index.html", ExpectStatus: []int{200}, ExpectBody: []string{"swagger", "Swagger"}, Severity: "info", RuleID: "dotnet-swagger", RuleName: "Swagger UI Exposed (.NET)", Description: "Swagger UI is accessible"},
			{Path: "/swagger/v1/swagger.json", ExpectStatus: []int{200}, ExpectBody: []string{"swagger", "paths"}, Severity: "info", RuleID: "dotnet-swagger-v1", RuleName: "Swagger v1 JSON (.NET)", Description: ".NET Swagger v1 JSON exposed"},
		},
	}
}

// ── Go / pprof ──

func goFuzzProbes() FuzzProbeSet {
	return FuzzProbeSet{
		Name:      "go-pprof",
		TechMatch: []string{"Go"},
		Probes: []FuzzProbe{
			{Path: "/debug/pprof/heap", ExpectStatus: []int{200}, Severity: "critical", RuleID: "go-pprof-heap", RuleName: "Go pprof Heap Dump Exposed", Description: "Heap profile downloadable"},
			{Path: "/debug/pprof/goroutine?debug=1", ExpectStatus: []int{200}, ExpectBody: []string{"goroutine", "runtime"}, Severity: "high", RuleID: "go-pprof-goroutine", RuleName: "Go pprof Goroutine Dump Exposed", Description: "Goroutine stacks expose code paths"},
			{Path: "/debug/pprof/cmdline", ExpectStatus: []int{200}, Severity: "high", RuleID: "go-pprof-cmdline", RuleName: "Go pprof Cmdline Exposed", Description: "Command line arguments may contain secrets"},
			{Path: "/debug/pprof/trace", ExpectStatus: []int{200}, Severity: "high", RuleID: "go-pprof-trace", RuleName: "Go pprof Trace Exposed", Description: "Execution tracer accessible"},
			{Path: "/debug/pprof/profile", ExpectStatus: []int{200}, Severity: "high", RuleID: "go-pprof-profile", RuleName: "Go pprof CPU Profile Exposed", Description: "CPU profiler accessible"},
			{Path: "/debug/pprof/mutex", ExpectStatus: []int{200}, Severity: "medium", RuleID: "go-pprof-mutex", RuleName: "Go pprof Mutex Profile Exposed", Description: "Mutex contention profile accessible"},
			{Path: "/debug/pprof/block", ExpectStatus: []int{200}, Severity: "medium", RuleID: "go-pprof-block", RuleName: "Go pprof Block Profile Exposed", Description: "Blocking profile accessible"},
			{Path: "/debug/vars", ExpectStatus: []int{200}, ExpectBody: []string{"cmdline", "memstats"}, RejectBody: []string{"<html"}, Severity: "medium", RuleID: "go-expvar", RuleName: "Go expvar Debug Variables Exposed", Description: "Application variables exposed as JSON"},
			{Path: "/debug/requests", ExpectStatus: []int{200}, ExpectBody: []string{"Trace", "Family"}, Severity: "medium", RuleID: "go-debug-requests", RuleName: "Go Debug Requests Exposed", Description: "golang.org/x/net/trace request traces exposed"},
			{Path: "/debug/events", ExpectStatus: []int{200}, ExpectBody: []string{"Event", "Family"}, Severity: "medium", RuleID: "go-debug-events", RuleName: "Go Debug Events Exposed", Description: "golang.org/x/net/trace events exposed"},
		},
	}
}

// ── AI/LLM Endpoints (Universal — often deployed without auth) ──

func aiLLMProbes() FuzzProbeSet {
	return FuzzProbeSet{
		Name:      "ai-llm",
		TechMatch: nil,
		Probes: []FuzzProbe{
			// Ollama
			{Path: "/api/tags", ExpectStatus: []int{200}, ExpectBody: []string{"models"}, RejectBody: []string{"<html", "<HTML"}, Severity: "high", RuleID: "ollama-api-tags", RuleName: "Ollama Model List Exposed", Description: "Ollama API listing all loaded models", Universal: true, TechDiscover: "Ollama"},
			{Path: "/api/version", ExpectStatus: []int{200}, ExpectBody: []string{"version"}, RejectBody: []string{"<html"}, Severity: "medium", RuleID: "ollama-version", RuleName: "Ollama Version Exposed", Description: "Ollama version information accessible", Universal: true},
			// OpenAI-compatible API (vLLM, LocalAI, LiteLLM, etc.)
			{Path: "/v1/models", ExpectStatus: []int{200}, ExpectBody: []string{`"data"`, `"id"`}, RejectBody: []string{"<html"}, Severity: "high", RuleID: "openai-compat-models", RuleName: "OpenAI-Compatible Model List Exposed", Description: "OpenAI-compatible API listing available models", Universal: true},
			// vLLM metrics
			{Path: "/metrics", ExpectStatus: []int{200}, ExpectBody: []string{"vllm:", "model_name"}, Severity: "medium", RuleID: "vllm-metrics", RuleName: "vLLM Prometheus Metrics Exposed", Description: "vLLM model serving metrics accessible", Universal: true, TechDiscover: "vLLM"},
			// LangServe
			{Path: "/docs", ExpectStatus: []int{200}, ExpectBody: []string{"LangServe"}, Severity: "medium", RuleID: "langserve-docs", RuleName: "LangServe API Docs Exposed", Description: "LangServe FastAPI documentation accessible", Universal: true, TechDiscover: "LangServe"},
			{Path: "/playground", ExpectStatus: []int{200}, ExpectBody: []string{"playground"}, RejectBody: []string{"Page Not Found", "404"}, Severity: "medium", RuleID: "langserve-playground", RuleName: "LangServe Playground Exposed", Description: "LangServe interactive playground accessible", Universal: true},
			// MLflow
			{Path: "/api/2.0/mlflow/experiments/search", ExpectStatus: []int{200}, ExpectBody: []string{"experiments"}, Severity: "high", RuleID: "mlflow-experiments", RuleName: "MLflow Experiments Exposed", Description: "MLflow experiment tracking API accessible without auth", Universal: true, TechDiscover: "MLflow"},
			{Path: "/ajax-api/2.0/mlflow/runs/search", ExpectStatus: []int{200}, ExpectBody: []string{"runs"}, Severity: "high", RuleID: "mlflow-runs", RuleName: "MLflow Runs Exposed", Description: "MLflow run data accessible without auth", Universal: true},
			// MCP (Model Context Protocol)
			{Path: "/.well-known/mcp.json", ExpectStatus: []int{200}, ExpectBody: []string{"capabilities"}, RejectBody: []string{"<html"}, Severity: "medium", RuleID: "mcp-manifest", RuleName: "MCP Manifest Exposed", Description: "Model Context Protocol server manifest accessible", Universal: true},
		},
	}
}

// ── Vector Databases (Universal — often deployed without auth) ──

func vectorDBProbes() FuzzProbeSet {
	return FuzzProbeSet{
		Name:      "vector-db",
		TechMatch: nil,
		Probes: []FuzzProbe{
			// Qdrant
			{Path: "/collections", ExpectStatus: []int{200}, ExpectBody: []string{"collections"}, RejectBody: []string{"<html", "<HTML"}, Severity: "high", RuleID: "qdrant-collections", RuleName: "Qdrant Collections Exposed", Description: "Qdrant vector database collections accessible without auth", Universal: true, TechDiscover: "Qdrant"},
			{Path: "/dashboard/", ExpectStatus: []int{200}, ExpectBody: []string{"Qdrant"}, Severity: "high", RuleID: "qdrant-dashboard", RuleName: "Qdrant Dashboard Exposed", Description: "Qdrant web dashboard accessible without auth", Universal: true},
			// Weaviate
			{Path: "/v1/schema", ExpectStatus: []int{200}, ExpectBody: []string{"classes"}, RejectBody: []string{"<html"}, Severity: "high", RuleID: "weaviate-schema", RuleName: "Weaviate Schema Exposed", Description: "Weaviate vector database schema accessible without auth", Universal: true, TechDiscover: "Weaviate"},
			{Path: "/v1/meta", ExpectStatus: []int{200}, ExpectBody: []string{"version"}, RejectBody: []string{"<html"}, Severity: "medium", RuleID: "weaviate-meta", RuleName: "Weaviate Meta Exposed", Description: "Weaviate version and meta information accessible", Universal: true},
			// ChromaDB
			{Path: "/api/v1/collections", ExpectStatus: []int{200}, ExpectBody: []string{"name"}, RejectBody: []string{"<html"}, Severity: "high", RuleID: "chromadb-collections", RuleName: "ChromaDB Collections Exposed", Description: "ChromaDB vector database collections accessible without auth", Universal: true, TechDiscover: "ChromaDB"},
			{Path: "/api/v1/heartbeat", ExpectStatus: []int{200}, ExpectBody: []string{"nanosecond heartbeat"}, Severity: "info", RuleID: "chromadb-heartbeat", RuleName: "ChromaDB Heartbeat Exposed", Description: "ChromaDB health endpoint accessible", Universal: true},
			// Milvus (Attu web UI)
			{Path: "/webui/", ExpectStatus: []int{200}, ExpectBody: []string{"Milvus"}, Severity: "high", RuleID: "milvus-webui", RuleName: "Milvus Web UI Exposed", Description: "Milvus vector database web interface accessible without auth", Universal: true, TechDiscover: "Milvus"},
		},
	}
}

// ── Quarkus (TechMatch: Quarkus/Java) ──

func quarkusFuzzProbes() FuzzProbeSet {
	return FuzzProbeSet{
		Name:      "quarkus",
		TechMatch: []string{"Quarkus"},
		Probes: []FuzzProbe{
			{Path: "/q/health", ExpectStatus: []int{200}, ExpectBody: []string{`"status"`, `"checks"`}, Severity: "medium", RuleID: "quarkus-health", RuleName: "Quarkus Health Endpoint Exposed", Description: "Quarkus SmallRye Health endpoint accessible"},
			{Path: "/q/health/live", ExpectStatus: []int{200}, ExpectBody: []string{`"status"`}, Severity: "info", RuleID: "quarkus-health-live", RuleName: "Quarkus Liveness Probe Exposed", Description: "Quarkus liveness probe accessible"},
			{Path: "/q/health/ready", ExpectStatus: []int{200}, ExpectBody: []string{`"status"`}, Severity: "info", RuleID: "quarkus-health-ready", RuleName: "Quarkus Readiness Probe Exposed", Description: "Quarkus readiness probe accessible"},
			{Path: "/q/metrics", ExpectStatus: []int{200}, ExpectBody: []string{"base_", "vendor_"}, RejectBody: []string{"<html"}, Severity: "medium", RuleID: "quarkus-metrics", RuleName: "Quarkus Metrics Exposed", Description: "Quarkus MicroProfile Metrics endpoint accessible"},
			{Path: "/q/openapi", ExpectStatus: []int{200}, ExpectBody: []string{"openapi", "paths"}, Severity: "info", RuleID: "quarkus-openapi", RuleName: "Quarkus OpenAPI Exposed", Description: "Quarkus OpenAPI spec accessible"},
			{Path: "/q/swagger-ui", ExpectStatus: []int{200}, ExpectBody: []string{"swagger"}, Severity: "info", RuleID: "quarkus-swagger", RuleName: "Quarkus Swagger UI Exposed", Description: "Quarkus Swagger UI accessible"},
			{Path: "/q/dev", ExpectStatus: []int{200}, ExpectBody: []string{"Quarkus", "Dev UI"}, Severity: "high", RuleID: "quarkus-dev-ui", RuleName: "Quarkus Dev UI Exposed", Description: "Quarkus Dev UI accessible — potential RCE via dev mode features"},
			{Path: "/q/arc/beans", ExpectStatus: []int{200}, ExpectBody: []string{"beans"}, RejectBody: []string{"<html"}, Severity: "medium", RuleID: "quarkus-arc-beans", RuleName: "Quarkus Arc Beans Exposed", Description: "Quarkus CDI bean listing accessible"},
			{Path: "/q/arc/observers", ExpectStatus: []int{200}, ExpectBody: []string{"observers"}, RejectBody: []string{"<html"}, Severity: "medium", RuleID: "quarkus-arc-observers", RuleName: "Quarkus Arc Observers Exposed", Description: "Quarkus CDI observer listing accessible"},
		},
	}
}

// ── Micronaut (TechMatch: Micronaut/Java) ──

func micronautFuzzProbes() FuzzProbeSet {
	return FuzzProbeSet{
		Name:      "micronaut",
		TechMatch: []string{"Micronaut"},
		Probes: []FuzzProbe{
			{Path: "/health", ExpectStatus: []int{200}, ExpectBody: []string{`"status"`, `"details"`}, RejectBody: []string{"<html"}, Severity: "info", RuleID: "micronaut-health", RuleName: "Micronaut Health Exposed", Description: "Micronaut health endpoint accessible"},
			{Path: "/beans", ExpectStatus: []int{200}, ExpectBody: []string{"beans"}, RejectBody: []string{"<html"}, Severity: "medium", RuleID: "micronaut-beans", RuleName: "Micronaut Beans Exposed", Description: "Micronaut bean listing accessible"},
			{Path: "/info", ExpectStatus: []int{200}, ExpectBody: []string{"build"}, RejectBody: []string{"<html"}, Severity: "info", RuleID: "micronaut-info", RuleName: "Micronaut Info Exposed", Description: "Micronaut build info accessible"},
			{Path: "/loggers", ExpectStatus: []int{200}, ExpectBody: []string{"loggers", "levels"}, RejectBody: []string{"<html"}, Severity: "medium", RuleID: "micronaut-loggers", RuleName: "Micronaut Loggers Exposed", Description: "Micronaut logger configuration accessible and modifiable"},
			{Path: "/routes", ExpectStatus: []int{200}, ExpectBody: []string{"routes"}, RejectBody: []string{"<html"}, Severity: "medium", RuleID: "micronaut-routes", RuleName: "Micronaut Routes Exposed", Description: "Micronaut route listing reveals all API endpoints"},
			{Path: "/env", ExpectStatus: []int{200}, ExpectBody: []string{"propertySources"}, Severity: "critical", RuleID: "micronaut-env", RuleName: "Micronaut Env Exposed", Description: "Micronaut environment properties exposed — may contain credentials"},
			{Path: "/refresh", Method: "POST", ExpectStatus: []int{200}, Severity: "high", RuleID: "micronaut-refresh", RuleName: "Micronaut Refresh Endpoint Exposed", Description: "Micronaut refresh endpoint can reload configuration"},
			{Path: "/threaddump", ExpectStatus: []int{200}, ExpectBody: []string{"threads"}, Severity: "high", RuleID: "micronaut-threaddump", RuleName: "Micronaut Thread Dump Exposed", Description: "Micronaut thread dump exposes internal execution"},
			{Path: "/metrics", ExpectStatus: []int{200}, ExpectBody: []string{"names"}, RejectBody: []string{"<html"}, Severity: "medium", RuleID: "micronaut-metrics", RuleName: "Micronaut Metrics Exposed", Description: "Micronaut metrics endpoint accessible"},
		},
	}
}

// ── DevOps/Cloud-Native Tools (Universal — infrastructure dashboards) ──

func devopsFuzzProbes() FuzzProbeSet {
	return FuzzProbeSet{
		Name:      "devops-cloud-native",
		TechMatch: nil,
		Probes: []FuzzProbe{
			// ArgoCD
			{Path: "/api/v1/applications", ExpectStatus: []int{200}, ExpectBody: []string{"items"}, RejectBody: []string{"<html"}, Severity: "high", RuleID: "argocd-applications", RuleName: "ArgoCD Applications Exposed", Description: "ArgoCD application list accessible without auth", Universal: true},
			{Path: "/argocd", ExpectStatus: []int{200}, ExpectBody: []string{"Argo CD"}, Severity: "high", RuleID: "argocd-ui", RuleName: "ArgoCD UI Exposed", Description: "ArgoCD web interface accessible", Universal: true},
			// HashiCorp Vault
			{Path: "/v1/sys/health", ExpectStatus: []int{200, 429, 472, 473, 501, 503}, ExpectBody: []string{"initialized"}, RejectBody: []string{"<html"}, Severity: "high", RuleID: "vault-health", RuleName: "HashiCorp Vault Health Exposed", Description: "Vault health endpoint accessible — reveals seal status", Universal: true},
			{Path: "/v1/sys/seal-status", ExpectStatus: []int{200}, ExpectBody: []string{"sealed"}, RejectBody: []string{"<html"}, Severity: "critical", RuleID: "vault-seal-status", RuleName: "HashiCorp Vault Seal Status Exposed", Description: "Vault seal status accessible — infrastructure at risk", Universal: true},
			{Path: "/ui/", ExpectStatus: []int{200}, ExpectBody: []string{"Vault"}, Severity: "high", RuleID: "vault-ui", RuleName: "HashiCorp Vault UI Exposed", Description: "Vault web UI accessible", Universal: true},
			// HashiCorp Consul
			{Path: "/v1/agent/self", ExpectStatus: []int{200}, ExpectBody: []string{"Config"}, RejectBody: []string{"<html"}, Severity: "high", RuleID: "consul-agent", RuleName: "Consul Agent API Exposed", Description: "Consul agent configuration accessible without auth", Universal: true},
			// HashiCorp Nomad
			{Path: "/v1/jobs", ExpectStatus: []int{200}, ExpectBody: []string{"ID"}, RejectBody: []string{"<html"}, Severity: "high", RuleID: "nomad-jobs", RuleName: "Nomad Jobs API Exposed", Description: "Nomad job list accessible without auth", Universal: true},
			// Prometheus
			{Path: "/api/v1/query", ExpectStatus: []int{200}, ExpectBody: []string{"status"}, RejectBody: []string{"<html"}, Severity: "medium", RuleID: "prometheus-api", RuleName: "Prometheus API Exposed", Description: "Prometheus query API accessible", Universal: true},
			{Path: "/graph", ExpectStatus: []int{200}, ExpectBody: []string{"Prometheus"}, Severity: "medium", RuleID: "prometheus-ui", RuleName: "Prometheus UI Exposed", Description: "Prometheus web UI accessible", Universal: true},
			{Path: "/targets", ExpectStatus: []int{200}, ExpectBody: []string{"scrapePool", "activeTargets"}, Severity: "medium", RuleID: "prometheus-targets", RuleName: "Prometheus Targets Exposed", Description: "Prometheus scrape targets reveal internal infrastructure", Universal: true},
			// Grafana
			{Path: "/api/health", ExpectStatus: []int{200}, ExpectBody: []string{"database"}, RejectBody: []string{"<html"}, Severity: "medium", RuleID: "grafana-health", RuleName: "Grafana Health Exposed", Description: "Grafana health endpoint accessible", Universal: true},
			{Path: "/api/dashboards/home", ExpectStatus: []int{200}, ExpectBody: []string{"dashboard"}, RejectBody: []string{"<html"}, Severity: "medium", RuleID: "grafana-dashboards", RuleName: "Grafana Dashboards Exposed", Description: "Grafana dashboards accessible without auth", Universal: true},
			{Path: "/login", ExpectStatus: []int{200}, ExpectBody: []string{"Grafana"}, Severity: "info", RuleID: "grafana-login", RuleName: "Grafana Login Found", Description: "Grafana login page detected", Universal: true},
			// Terraform
			{Path: "/.terraform/terraform.tfstate", ExpectStatus: []int{200}, ExpectBody: []string{"terraform_version"}, RejectBody: []string{"<html"}, Severity: "critical", RuleID: "terraform-state", RuleName: "Terraform State File Exposed", Description: "Terraform state file contains infrastructure secrets and credentials", Universal: true},
			// Portainer
			{Path: "/portainer/", ExpectStatus: []int{200}, ExpectBody: []string{"Portainer"}, Severity: "high", RuleID: "portainer-ui", RuleName: "Portainer UI Exposed", Description: "Portainer Docker management UI accessible", Universal: true},
			{Path: "/api/endpoints", ExpectStatus: []int{200}, ExpectBody: []string{"Endpoints"}, RejectBody: []string{"<html"}, Severity: "high", RuleID: "portainer-api", RuleName: "Portainer API Exposed", Description: "Portainer API accessible — Docker control", Universal: true},
		},
	}
}

// ── Config/Secret Files (Universal — deployment artifacts) ──

func configFileProbes() FuzzProbeSet {
	return FuzzProbeSet{
		Name:      "config-files",
		TechMatch: nil,
		Probes: []FuzzProbe{
			// .env variants
			{Path: "/.env.local", ExpectStatus: []int{200}, ExpectBody: []string{"DB_", "API_", "SECRET", "PASSWORD", "KEY"}, RejectBody: []string{"<html", "<HTML", "<!DOCTYPE"}, Severity: "critical", RuleID: "env-local", RuleName: ".env.local Exposed", Description: "Local environment file with secrets accessible", Universal: true},
			{Path: "/.env.production", ExpectStatus: []int{200}, ExpectBody: []string{"DB_", "API_", "SECRET", "PASSWORD", "KEY"}, RejectBody: []string{"<html", "<HTML", "<!DOCTYPE"}, Severity: "critical", RuleID: "env-production", RuleName: ".env.production Exposed", Description: "Production environment file with secrets accessible", Universal: true},
			{Path: "/.env.staging", ExpectStatus: []int{200}, ExpectBody: []string{"DB_", "API_", "SECRET", "PASSWORD", "KEY"}, RejectBody: []string{"<html", "<HTML", "<!DOCTYPE"}, Severity: "critical", RuleID: "env-staging", RuleName: ".env.staging Exposed", Description: "Staging environment file accessible", Universal: true},
			{Path: "/.env.development", ExpectStatus: []int{200}, ExpectBody: []string{"DB_", "API_", "SECRET", "PASSWORD", "KEY"}, RejectBody: []string{"<html", "<HTML", "<!DOCTYPE"}, Severity: "high", RuleID: "env-development", RuleName: ".env.development Exposed", Description: "Development environment file accessible", Universal: true},
			{Path: "/.env.backup", ExpectStatus: []int{200}, ExpectBody: []string{"DB_", "API_", "SECRET", "PASSWORD", "KEY"}, RejectBody: []string{"<html", "<HTML", "<!DOCTYPE"}, Severity: "critical", RuleID: "env-backup", RuleName: ".env.backup Exposed", Description: "Backup of environment file accessible", Universal: true},
			// Cloud platform configs
			{Path: "/wrangler.toml", ExpectStatus: []int{200}, ExpectBody: []string{"name", "compatibility"}, RejectBody: []string{"<html", "<HTML"}, Severity: "high", RuleID: "cloudflare-wrangler", RuleName: "Cloudflare Workers Config Exposed", Description: "wrangler.toml reveals Cloudflare Workers configuration", Universal: true},
			{Path: "/fly.toml", ExpectStatus: []int{200}, ExpectBody: []string{"app", "primary_region"}, RejectBody: []string{"<html", "<HTML"}, Severity: "medium", RuleID: "fly-config", RuleName: "Fly.io Config Exposed", Description: "fly.toml reveals deployment configuration", Universal: true},
			// Docker
			{Path: "/docker-compose.yml", ExpectStatus: []int{200}, ExpectBody: []string{"services", "image"}, RejectBody: []string{"<html", "<HTML"}, Severity: "high", RuleID: "docker-compose-yml", RuleName: "Docker Compose File Exposed", Description: "docker-compose.yml reveals service architecture and may contain credentials", Universal: true},
			{Path: "/docker-compose.yaml", ExpectStatus: []int{200}, ExpectBody: []string{"services", "image"}, RejectBody: []string{"<html", "<HTML"}, Severity: "high", RuleID: "docker-compose-yaml", RuleName: "Docker Compose File Exposed", Description: "docker-compose.yaml reveals service architecture", Universal: true},
			{Path: "/Dockerfile", ExpectStatus: []int{200}, ExpectBody: []string{"FROM", "RUN"}, RejectBody: []string{"<html", "<HTML"}, Severity: "medium", RuleID: "dockerfile-exposed", RuleName: "Dockerfile Exposed", Description: "Dockerfile reveals build process and base images", Universal: true},
			// ORM/DB schemas
			{Path: "/prisma/schema.prisma", ExpectStatus: []int{200}, ExpectBody: []string{"datasource", "model"}, RejectBody: []string{"<html"}, Severity: "high", RuleID: "prisma-schema", RuleName: "Prisma Schema Exposed", Description: "Prisma schema reveals database structure and connection info", Universal: true},
			// Package manifests
			{Path: "/composer.json", ExpectStatus: []int{200}, ExpectBody: []string{"require", "name"}, RejectBody: []string{"<html"}, Severity: "medium", RuleID: "php-composer-json", RuleName: "PHP Composer JSON Exposed", Description: "PHP composer.json reveals dependencies and versions", Universal: true},
			{Path: "/Gemfile", ExpectStatus: []int{200}, ExpectBody: []string{"source", "gem"}, RejectBody: []string{"<html"}, Severity: "medium", RuleID: "ruby-gemfile", RuleName: "Ruby Gemfile Exposed", Description: "Gemfile reveals Ruby dependencies", Universal: true},
			{Path: "/Cargo.toml", ExpectStatus: []int{200}, ExpectBody: []string{"[package]", "name"}, RejectBody: []string{"<html"}, Severity: "info", RuleID: "rust-cargo-toml", RuleName: "Rust Cargo.toml Exposed", Description: "Cargo.toml reveals Rust package configuration", Universal: true},
		},
	}
}

// ── Modern JS Frameworks (Nuxt DevTools, tRPC, Scalar) ──

func modernJSFuzzProbes() FuzzProbeSet {
	return FuzzProbeSet{
		Name:      "modern-js",
		TechMatch: []string{"Nuxt", "Next.js", "Elysia", "Bun", "Hono"},
		Probes: []FuzzProbe{
			{Path: "/__nuxt_devtools__/client/", ExpectStatus: []int{200}, ExpectBody: []string{"Nuxt DevTools"}, Severity: "high", RuleID: "nuxt-devtools", RuleName: "Nuxt DevTools Exposed", Description: "Nuxt DevTools accessible in production — reveals internal state"},
			{Path: "/_nuxt/builds/latest.json", ExpectStatus: []int{200}, ExpectBody: []string{"id"}, RejectBody: []string{"<html"}, Severity: "info", RuleID: "nuxt-build-info", RuleName: "Nuxt Build Info Exposed", Description: "Nuxt build information accessible"},
			{Path: "/api/trpc", ExpectStatus: []int{200, 400, 500}, ExpectBody: []string{"error", "result"}, Severity: "info", RuleID: "trpc-endpoint", RuleName: "tRPC Endpoint Found", Description: "tRPC API endpoint detected"},
			{Path: "/trpc", ExpectStatus: []int{200, 400, 500}, ExpectBody: []string{"error", "result"}, Severity: "info", RuleID: "trpc-endpoint-alt", RuleName: "tRPC Endpoint Found (alt)", Description: "tRPC API endpoint detected at alternative path"},
			{Path: "/reference", ExpectStatus: []int{200}, ExpectBody: []string{"Scalar", "openapi"}, Severity: "info", RuleID: "scalar-api-docs", RuleName: "Scalar API Docs Exposed", Description: "Scalar API documentation accessible"},
		},
	}
}
