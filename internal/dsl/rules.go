package dsl

import (
	"embed"
	"fmt"
	"os"
	"regexp"

	"gopkg.in/yaml.v3"
)

//go:embed rules/default.yaml
var defaultRulesFS embed.FS

// LoadDefaultRules loads the built-in default rules.
func LoadDefaultRules() ([]Rule, error) {
	data, err := defaultRulesFS.ReadFile("rules/default.yaml")
	if err != nil {
		return nil, fmt.Errorf("read default rules: %w", err)
	}

	var rs RuleSet
	if err := yaml.Unmarshal(data, &rs); err != nil {
		return nil, fmt.Errorf("parse default rules: %w", err)
	}

	return rs.Rules, nil
}

// LoadCustomRules loads rules from a user-provided YAML file.
func LoadCustomRules(path string) ([]Rule, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read custom rules %s: %w", path, err)
	}

	var rs RuleSet
	if err := yaml.Unmarshal(data, &rs); err != nil {
		return nil, fmt.Errorf("parse custom rules %s: %w", path, err)
	}

	return rs.Rules, nil
}

// MergeRules merges default and custom rules. Custom rules with the same ID override defaults.
func MergeRules(defaults, custom []Rule) []Rule {
	byID := make(map[string]Rule, len(defaults)+len(custom))
	var order []string

	for _, r := range defaults {
		byID[r.ID] = r
		order = append(order, r.ID)
	}
	for _, r := range custom {
		if _, exists := byID[r.ID]; !exists {
			order = append(order, r.ID)
		}
		byID[r.ID] = r
	}

	result := make([]Rule, 0, len(order))
	for _, id := range order {
		result = append(result, byID[id])
	}
	return result
}

// CompileRules compiles regex patterns for all rules.
func CompileRules(rules []Rule) error {
	for i := range rules {
		re, err := regexp.Compile(rules[i].Pattern)
		if err != nil {
			return fmt.Errorf("rule %s: invalid pattern %q: %w", rules[i].ID, rules[i].Pattern, err)
		}
		rules[i].Compiled = re
	}
	return nil
}
