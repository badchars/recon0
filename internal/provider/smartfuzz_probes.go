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

// pathPrefixes are prepended to tech-specific probes for path variation discovery.
var pathPrefixes = []string{
	"",
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
	}
}

// ExpandWithPrefixes generates path variations for a probe using pathPrefixes.
func ExpandWithPrefixes(probe FuzzProbe) []FuzzProbe {
	var expanded []FuzzProbe
	for _, prefix := range pathPrefixes {
		p := probe
		p.Path = prefix + probe.Path
		if prefix != "" {
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
