package netpolicy

import "regexp"

// Template is one policy rule in Nuclei-style YAML format.
type Template struct {
	ID     string       `yaml:"id"`
	Info   TemplateInfo `yaml:"info"`
	Match  MatchSpec    `yaml:"match"`
	Scan   *ScanSpec    `yaml:"scan,omitempty"`
	Action string       `yaml:"action"` // "allow", "ask", "deny"
	Reason string       `yaml:"reason"` // supports {{.Verb}}, {{.ResourceType}} etc.
	Impact string       `yaml:"impact,omitempty"`
}

// TemplateInfo holds metadata about a template.
type TemplateInfo struct {
	Name     string   `yaml:"name"`
	Author   string   `yaml:"author"`
	Severity string   `yaml:"severity"` // "info", "low", "medium", "high", "critical"
	Tags     []string `yaml:"tags"`
}

// MatchSpec defines which operations this template applies to.
// All fields are optional. A zero-value field matches everything.
// Multiple values in a list field are OR'd. All present fields are AND'd.
type MatchSpec struct {
	Protocol     []string `yaml:"protocol,omitempty"`
	Service      []string `yaml:"service,omitempty"`
	Verb         []string `yaml:"verb,omitempty"`
	ResourceType []string `yaml:"resource_type,omitempty"`
	ResourceName []string `yaml:"resource_name,omitempty"` // supports glob patterns
	Namespace    []string `yaml:"namespace,omitempty"`      // supports glob patterns
	Host         []string `yaml:"host,omitempty"`           // supports glob patterns
	Method       []string `yaml:"method,omitempty"`
	Path         []string `yaml:"path,omitempty"` // supports glob and regex (prefixed with "re:")
}

// ScanSpec defines content scanning rules applied to the payload/body.
type ScanSpec struct {
	Payload []ScanRule `yaml:"payload,omitempty"`
	Headers []ScanRule `yaml:"headers,omitempty"`
	Query   []ScanRule `yaml:"query,omitempty"`
}

// ScanRule is a single content-scanning rule within a ScanSpec.
type ScanRule struct {
	Type     string   `yaml:"type"`               // "regex", "contains", "not_contains"
	Patterns []string `yaml:"patterns"`
	Name     string   `yaml:"name,omitempty"`      // label for the finding, e.g. "SSN", "Credit Card"

	// compiledPatterns holds pre-compiled regexps for type "regex".
	// Populated at template load time via compilePatterns().
	compiledPatterns []*regexp.Regexp
}

// compilePatterns pre-compiles regex patterns for this rule.
// Called once at template load time. Returns an error for invalid regexps.
func (r *ScanRule) compilePatterns() error {
	if r.Type != "regex" {
		return nil
	}
	r.compiledPatterns = make([]*regexp.Regexp, 0, len(r.Patterns))
	for _, p := range r.Patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return err
		}
		r.compiledPatterns = append(r.compiledPatterns, re)
	}
	return nil
}
