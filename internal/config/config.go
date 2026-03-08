package config

import (
	"fmt"
	"os"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level recon0 configuration.
type Config struct {
	OutputDir string                    `yaml:"output_dir"`
	Resume    bool                      `yaml:"resume"`
	DiskMinGB int                       `yaml:"disk_min_gb"`
	URLCap    int                       `yaml:"url_cap"`
	Resources ResourcesConfig           `yaml:"resources"`
	Log       LogConfig                 `yaml:"log"`
	API       APIConfig                 `yaml:"api"`
	Providers map[string]ProviderConfig `yaml:"providers"`
}

// APIConfig controls the HTTP status API.
type APIConfig struct {
	Enabled bool   `yaml:"enabled"`
	Port    int    `yaml:"port"`
	Listen  string `yaml:"listen"`
}

// ResourcesConfig controls thread/rate auto-detection.
type ResourcesConfig struct {
	Auto       bool `yaml:"auto"`
	MaxThreads int  `yaml:"max_threads"`
	MaxRate    int  `yaml:"max_rate"`
}

// LogConfig controls logging behavior.
type LogConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
	File   bool   `yaml:"file"`
}

// ProviderConfig holds per-provider settings.
type ProviderConfig struct {
	Enabled *bool          `yaml:"enabled"`
	Extra   map[string]any `yaml:",inline"`
}

func boolPtr(b bool) *bool { return &b }

// Defaults returns a config with sensible defaults.
func Defaults() *Config {
	return &Config{
		OutputDir: "./runs",
		Resume:    true,
		DiskMinGB: 20,
		URLCap:    2000000,
		Resources: ResourcesConfig{
			Auto:       true,
			MaxThreads: 0,
			MaxRate:    5000,
		},
		Log: LogConfig{
			Level:  "info",
			Format: "color",
			File:   true,
		},
		API: APIConfig{
			Enabled: true,
			Port:    8484,
			Listen:  "0.0.0.0",
		},
		Providers: map[string]ProviderConfig{
			"subfinder": {Enabled: boolPtr(true), Extra: map[string]any{"timeout": 30}},
			"amass":     {Enabled: boolPtr(true), Extra: map[string]any{"timeout": 30}},
			"dnsx":      {Enabled: boolPtr(true)},
			"httpx":     {Enabled: boolPtr(true), Extra: map[string]any{"ports": []any{80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 9090}}},
			"tlsx":      {Enabled: boolPtr(true)},
			"cdpcrawl": {Enabled: boolPtr(true), Extra: map[string]any{
				"headless":            true,
				"timeout_per_page":    "30s",
				"max_pages_per_host":  50,
				"click_depth":         2,
				"max_concurrent_tabs": 5,
				"user_agent":          "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36",
				"viewport_width":      1920,
				"viewport_height":     1080,
			}},
			"naabu":    {Enabled: boolPtr(false), Extra: map[string]any{"top_ports": 100}},
			"discover": {Enabled: boolPtr(true)},
			"analyzer": {Enabled: boolPtr(true), Extra: map[string]any{"custom_rules": ""}},
			"collector": {Enabled: boolPtr(true), Extra: map[string]any{
				"llm_enabled":    false,
				"llm_provider":   "openai",
				"llm_model":      "gpt-oss-120b", // placeholder for a local LLM
				"llm_api_key":    "",
				"llm_base_url":   "",
				"llm_max_tokens": 4096,
			}},
			"nuclei":      {Enabled: boolPtr(false), Extra: map[string]any{"severity": []any{"medium", "high", "critical"}}},
			"smartfuzz": {Enabled: boolPtr(true), Extra: map[string]any{
				"timeout":            "10s",
				"max_concurrent":     30,
				"skip_cors":          false,
				"cdn_mode":           "critical_only",
				"prefix_expansion":   true,
				"discovery_fuzz":     true,
				"max_probes_per_host": 500,
			}},
		},
	}
}

// Load reads a YAML config file and merges with defaults.
func Load(path string) (*Config, error) {
	cfg := Defaults()

	if path == "" {
		if envPath := os.Getenv("RECON0_CONFIG"); envPath != "" {
			path = envPath
		}
	}

	if path != "" {
		data, err := os.ReadFile(path)
		if err != nil {
			return nil, fmt.Errorf("read config: %w", err)
		}

		// Parse user config into a separate struct to detect which providers were specified
		var userCfg Config
		if err := yaml.Unmarshal(data, &userCfg); err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}

		// Apply non-provider settings from user config
		// Re-unmarshal into defaults so top-level fields get overridden
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, fmt.Errorf("parse config: %w", err)
		}

		// Restore default providers, then merge user overrides on top
		defaults := Defaults()
		merged := make(map[string]ProviderConfig, len(defaults.Providers))
		for name, def := range defaults.Providers {
			merged[name] = def
		}
		for name, userProv := range userCfg.Providers {
			def, hasDefault := merged[name]
			if hasDefault {
				// Merge Extra: user values override defaults
				if userProv.Extra != nil {
					if def.Extra == nil {
						def.Extra = make(map[string]any)
					}
					for k, v := range userProv.Extra {
						def.Extra[k] = v
					}
				}
				// Only override Enabled if user explicitly set it (non-nil)
				if userProv.Enabled != nil {
					def.Enabled = userProv.Enabled
				}
				merged[name] = def
			} else {
				// New provider only in user config
				if userProv.Enabled == nil {
					userProv.Enabled = boolPtr(true) // assume enabled if user defined it
				}
				merged[name] = userProv
			}
		}
		cfg.Providers = merged
	}

	applyEnvOverrides(cfg)

	return cfg, nil
}

// ProviderEnabled checks if a provider is enabled in config.
func (c *Config) ProviderEnabled(name string) bool {
	p, ok := c.Providers[name]
	if !ok {
		return false
	}
	if p.Enabled == nil {
		return false
	}
	return *p.Enabled
}

// ProviderExtra returns provider-specific config values.
func (c *Config) ProviderExtra(name string) map[string]any {
	p, ok := c.Providers[name]
	if !ok {
		return nil
	}
	return p.Extra
}

// GetString extracts a string from provider extra config.
func GetString(extra map[string]any, key, fallback string) string {
	if extra == nil {
		return fallback
	}
	v, ok := extra[key]
	if !ok {
		return fallback
	}
	s, ok := v.(string)
	if !ok {
		return fallback
	}
	return s
}

// GetInt extracts an int from provider extra config.
func GetInt(extra map[string]any, key string, fallback int) int {
	if extra == nil {
		return fallback
	}
	v, ok := extra[key]
	if !ok {
		return fallback
	}
	switch n := v.(type) {
	case int:
		return n
	case float64:
		return int(n)
	default:
		return fallback
	}
}

// GetBool extracts a bool from provider extra config.
func GetBool(extra map[string]any, key string, fallback bool) bool {
	if extra == nil {
		return fallback
	}
	v, ok := extra[key]
	if !ok {
		return fallback
	}
	b, ok := v.(bool)
	if !ok {
		return fallback
	}
	return b
}

// GetDuration extracts a duration string from provider extra config.
func GetDuration(extra map[string]any, key string, fallback time.Duration) time.Duration {
	s := GetString(extra, key, "")
	if s == "" {
		return fallback
	}
	d, err := time.ParseDuration(s)
	if err != nil {
		return fallback
	}
	return d
}

// GetStringSlice extracts a string slice from provider extra config.
func GetStringSlice(extra map[string]any, key string, fallback []string) []string {
	if extra == nil {
		return fallback
	}
	v, ok := extra[key]
	if !ok {
		return fallback
	}
	switch s := v.(type) {
	case []string:
		return s
	case []any:
		result := make([]string, 0, len(s))
		for _, item := range s {
			if str, ok := item.(string); ok {
				result = append(result, str)
			}
		}
		return result
	default:
		return fallback
	}
}

// GetIntSlice extracts an int slice from provider extra config.
func GetIntSlice(extra map[string]any, key string, fallback []int) []int {
	if extra == nil {
		return fallback
	}
	v, ok := extra[key]
	if !ok {
		return fallback
	}
	switch s := v.(type) {
	case []int:
		return s
	case []any:
		result := make([]int, 0, len(s))
		for _, item := range s {
			switch n := item.(type) {
			case int:
				result = append(result, n)
			case float64:
				result = append(result, int(n))
			}
		}
		return result
	default:
		return fallback
	}
}

func applyEnvOverrides(cfg *Config) {
	if v := os.Getenv("RECON0_OUTPUT"); v != "" {
		cfg.OutputDir = v
	}
	if v := os.Getenv("RECON0_LOG_LEVEL"); v != "" {
		cfg.Log.Level = v
	}
	if v := os.Getenv("RECON0_LOG_FORMAT"); v != "" {
		cfg.Log.Format = v
	}
	if v := os.Getenv("RECON0_RESUME"); v == "false" {
		cfg.Resume = false
	}
	if v := os.Getenv("RECON0_LLM_API_KEY"); v != "" {
		if p, ok := cfg.Providers["collector"]; ok {
			if p.Extra == nil {
				p.Extra = make(map[string]any)
			}
			p.Extra["llm_api_key"] = v
			cfg.Providers["collector"] = p
		}
	}
}
