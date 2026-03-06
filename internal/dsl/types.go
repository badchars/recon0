package dsl

import "regexp"

// Severity levels for findings.
type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
	SeverityInfo     Severity = "info"
)

// RuleSource indicates what content a rule should scan.
type RuleSource string

const (
	SourceHAR        RuleSource = "har"
	SourceHARHeaders RuleSource = "har_headers"
	SourceJS         RuleSource = "js"
	SourceHTML       RuleSource = "html"
	SourceEndpoints  RuleSource = "endpoints"
)

// Rule defines a single detection rule.
type Rule struct {
	ID       string       `yaml:"id" json:"id"`
	Name     string       `yaml:"name" json:"name"`
	Severity Severity     `yaml:"severity" json:"severity"`
	Pattern  string       `yaml:"pattern" json:"pattern"`
	Compiled *regexp.Regexp `yaml:"-" json:"-"`
	Sources  []RuleSource `yaml:"source" json:"source"`
	Tags     []string     `yaml:"tags,omitempty" json:"tags,omitempty"`
	FalsePos []string     `yaml:"false_positive,omitempty" json:"false_positive,omitempty"`
}

// Finding represents a single detection result.
type Finding struct {
	RuleID   string   `json:"rule_id"`
	RuleName string   `json:"rule_name"`
	Severity Severity `json:"severity"`
	Value    string   `json:"value"`
	Source   string   `json:"source"`
	File     string   `json:"file"`
	Line     int      `json:"line,omitempty"`
	URL      string   `json:"url,omitempty"`
	Context  string   `json:"context,omitempty"`
}

// RuleSet is a collection of rules loaded from YAML.
type RuleSet struct {
	Rules []Rule `yaml:"rules" json:"rules"`
}
