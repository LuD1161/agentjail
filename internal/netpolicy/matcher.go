package netpolicy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"text/template"

	"go.yaml.in/yaml/v3"
)

// Matcher loads templates and evaluates operations against them.
type Matcher struct {
	templates []Template
}

// MatchResult is the outcome of evaluating an operation against templates.
type MatchResult struct {
	Template *Template
	Action   string    // "allow", "ask", "deny"
	Reason   string    // with template variables expanded
	Impact   string    // with template variables expanded
	ScanHits []ScanHit // any PII/pattern matches found
}

// ScanHit records a single content-scan match.
type ScanHit struct {
	RuleName string // e.g. "SSN", "Credit Card"
	Pattern  string // the regex/pattern that matched
	Location string // "payload.messages[0].content", "headers.Authorization"
}

// NewMatcher creates a matcher from template directories.
// It reads all .yaml files from each directory and compiles them.
func NewMatcher(templateDirs ...string) (*Matcher, error) {
	var all []Template
	for _, dir := range templateDirs {
		ts, err := LoadTemplates(dir)
		if err != nil {
			return nil, fmt.Errorf("loading templates from %s: %w", dir, err)
		}
		all = append(all, ts...)
	}
	return &Matcher{templates: all}, nil
}

// ValidateDir reports whether every template in dir parses and is meaningful.
// It exists so a launch path can refuse a malformed template up front, instead
// of discovering it somewhere that fails open. AGE-227.
func ValidateDir(dir string) error {
	_, err := LoadTemplates(dir)
	return err
}

// LoadTemplates reads all .yaml files from a directory.
// Files may contain multiple YAML documents separated by "---".
func LoadTemplates(dir string) ([]Template, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	var templates []Template
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		ext := filepath.Ext(e.Name())
		if ext != ".yaml" && ext != ".yml" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, fmt.Errorf("reading %s: %w", e.Name(), err)
		}
		ts, err := parseTemplates(data)
		if err != nil {
			return nil, fmt.Errorf("parsing %s: %w", e.Name(), err)
		}
		templates = append(templates, ts...)
	}
	return templates, nil
}

// parseTemplates parses YAML data that may contain multiple documents
// separated by "---".
//
// Decoding is strict (KnownFields). A template whose shape is wrong used to
// load silently as an empty MatchSpec -- which matches everything -- with an
// empty action, so it enforced nothing while looking installed. A policy that
// silently does nothing is the failure this project exists to prevent, so a
// template we cannot understand is an error, not a shrug. AGE-227.
func parseTemplates(data []byte) ([]Template, error) {
	var templates []Template
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	for {
		var t Template
		err := dec.Decode(&t)
		if err != nil {
			// io.EOF means we've consumed all documents.
			if err.Error() == "EOF" {
				break
			}
			return nil, err
		}
		// Skip genuinely empty documents (e.g. a trailing "---"), but a
		// document with content and no id is a mistake, not a blank.
		if isZeroTemplate(&t) {
			continue
		}
		if err := validateTemplate(&t); err != nil {
			return nil, err
		}
		if err := compileScanRules(&t); err != nil {
			return nil, fmt.Errorf("template %s: %w", t.ID, err)
		}
		templates = append(templates, t)
	}
	return templates, nil
}

// isZeroTemplate reports whether a decoded document carried no fields at all.
func isZeroTemplate(t *Template) bool {
	return reflect.DeepEqual(*t, Template{})
}

// validActions is the closed set of actions the matcher can act on. Anything
// else scores 0 in actionPriority and is silently a no-op, so it is rejected
// here rather than at request time.
var validActions = map[string]bool{"allow": true, "ask": true, "deny": true}

// validateTemplate rejects a template that would load but never do anything.
func validateTemplate(t *Template) error {
	if t.ID == "" {
		return fmt.Errorf("template is missing an id (name=%q)", t.Info.Name)
	}
	if t.Action == "" {
		return fmt.Errorf("template %s has no action: expected one of allow, ask, deny", t.ID)
	}
	if !validActions[strings.ToLower(t.Action)] {
		return fmt.Errorf("template %s has action %q: expected one of allow, ask, deny", t.ID, t.Action)
	}
	return nil
}

// compileScanRules pre-compiles regex patterns in all scan rules of a template.
func compileScanRules(t *Template) error {
	if t.Scan == nil {
		return nil
	}
	for i := range t.Scan.Payload {
		if err := t.Scan.Payload[i].compilePatterns(); err != nil {
			return err
		}
	}
	for i := range t.Scan.Headers {
		if err := t.Scan.Headers[i].compilePatterns(); err != nil {
			return err
		}
	}
	for i := range t.Scan.Query {
		if err := t.Scan.Query[i].compilePatterns(); err != nil {
			return err
		}
	}
	return nil
}

// Evaluate checks an operation against all loaded templates.
// Returns the most restrictive matching decision (deny > ask > allow).
// Returns nil if no template matches (default: allow).
func (m *Matcher) Evaluate(op *Operation) *MatchResult {
	var best *MatchResult

	for i := range m.templates {
		t := &m.templates[i]
		if !matchSpec(&t.Match, op) {
			continue
		}

		hits := scanOperation(t.Scan, op)

		// If the template has scan rules but nothing matched, skip it.
		if t.Scan != nil && hasScanRules(t.Scan) && len(hits) == 0 {
			continue
		}

		result := &MatchResult{
			Template: t,
			Action:   t.Action,
			Reason:   expandTemplate(t.Reason, op, hits),
			Impact:   expandTemplate(t.Impact, op, hits),
			ScanHits: hits,
		}

		if best == nil || moreRestrictive(result, best) {
			best = result
		}
	}

	return best
}

// hasScanRules returns true if the ScanSpec has any rules defined.
func hasScanRules(s *ScanSpec) bool {
	return len(s.Payload) > 0 || len(s.Headers) > 0 || len(s.Query) > 0
}

// actionPriority returns a numeric priority for action levels.
// Higher number = more restrictive.
func actionPriority(action string) int {
	switch strings.ToLower(action) {
	case "deny":
		return 3
	case "ask":
		return 2
	case "allow":
		return 1
	default:
		return 0
	}
}

// severityPriority returns a numeric priority for severity levels.
func severityPriority(sev string) int {
	switch strings.ToLower(sev) {
	case "critical":
		return 5
	case "high":
		return 4
	case "medium":
		return 3
	case "low":
		return 2
	case "info":
		return 1
	default:
		return 0
	}
}

// moreRestrictive returns true if a is more restrictive than b.
func moreRestrictive(a, b *MatchResult) bool {
	ap, bp := actionPriority(a.Action), actionPriority(b.Action)
	if ap != bp {
		return ap > bp
	}
	return severityPriority(a.Template.Info.Severity) > severityPriority(b.Template.Info.Severity)
}

// matchSpec checks if an operation matches all fields in the spec.
// Empty list fields match everything. All present fields are AND'd.
func matchSpec(spec *MatchSpec, op *Operation) bool {
	if !matchStringList(spec.Protocol, op.Protocol) {
		return false
	}
	if !matchStringList(spec.Service, op.Service) {
		return false
	}
	if !matchStringList(spec.Verb, op.Verb) {
		return false
	}
	if !matchStringList(spec.ResourceType, op.ResourceType) {
		return false
	}
	if !matchGlobList(spec.ResourceName, op.ResourceName) {
		return false
	}
	if !matchGlobList(spec.Namespace, op.Namespace) {
		return false
	}
	if !matchGlobList(spec.Host, op.Host) {
		return false
	}
	if !matchPortList(spec.Port, op.Port) {
		return false
	}
	if !matchStringList(spec.Method, op.Method) {
		return false
	}
	if !matchPathList(spec.Path, op.Path) {
		return false
	}
	return true
}

func matchPortList(patterns []Port, value Port) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, pattern := range patterns {
		if pattern == value {
			return true
		}
	}
	return false
}

// matchStringList checks if value is in the patterns list (case-insensitive).
// An empty patterns list matches everything.
func matchStringList(patterns []string, value string) bool {
	if len(patterns) == 0 {
		return true
	}
	lower := strings.ToLower(value)
	for _, p := range patterns {
		if strings.ToLower(p) == lower {
			return true
		}
	}
	return false
}

// matchGlobList checks if value matches any pattern in the list.
// Patterns containing * or ? are treated as glob patterns (filepath.Match).
// Others are compared case-insensitively.
// An empty patterns list matches everything.
func matchGlobList(patterns []string, value string) bool {
	if len(patterns) == 0 {
		return true
	}
	lower := strings.ToLower(value)
	for _, p := range patterns {
		pl := strings.ToLower(p)
		if strings.ContainsAny(p, "*?") {
			if ok, _ := filepath.Match(pl, lower); ok {
				return true
			}
		} else if pl == lower {
			return true
		}
	}
	return false
}

// matchPathList checks if a path matches any pattern in the list.
// Patterns prefixed with "re:" are treated as regexps.
// Patterns with * or ? are treated as globs.
// Others are compared case-insensitively.
func matchPathList(patterns []string, value string) bool {
	if len(patterns) == 0 {
		return true
	}
	lower := strings.ToLower(value)
	for _, p := range patterns {
		if strings.HasPrefix(p, "re:") {
			re, err := regexp.Compile(p[3:])
			if err != nil {
				continue
			}
			if re.MatchString(value) {
				return true
			}
		} else if strings.ContainsAny(p, "*?") {
			if ok, _ := filepath.Match(strings.ToLower(p), lower); ok {
				return true
			}
		} else if strings.ToLower(p) == lower {
			return true
		}
	}
	return false
}

// scanOperation runs all scan rules against the operation's content.
func scanOperation(spec *ScanSpec, op *Operation) []ScanHit {
	if spec == nil {
		return nil
	}
	var hits []ScanHit

	if len(spec.Payload) > 0 && op.Payload != nil {
		payloadJSON, err := json.Marshal(op.Payload)
		if err == nil {
			for _, rule := range spec.Payload {
				hits = append(hits, scanContent(rule, string(payloadJSON), "payload")...)
			}
		}
	}

	if len(spec.Headers) > 0 && op.Headers != nil {
		var sb strings.Builder
		for k, v := range op.Headers {
			sb.WriteString(k)
			sb.WriteString("=")
			sb.WriteString(v)
			sb.WriteString("\n")
		}
		headerStr := sb.String()
		for _, rule := range spec.Headers {
			hits = append(hits, scanContent(rule, headerStr, "headers")...)
		}
	}

	if len(spec.Query) > 0 && op.RawQuery != "" {
		for _, rule := range spec.Query {
			hits = append(hits, scanContent(rule, op.RawQuery, "query")...)
		}
	}

	return hits
}

// scanContent checks a single scan rule against content.
func scanContent(rule ScanRule, content, location string) []ScanHit {
	var hits []ScanHit
	switch rule.Type {
	case "regex":
		for i, re := range rule.compiledPatterns {
			if re.MatchString(content) {
				pattern := ""
				if i < len(rule.Patterns) {
					pattern = rule.Patterns[i]
				}
				hits = append(hits, ScanHit{
					RuleName: rule.Name,
					Pattern:  pattern,
					Location: location,
				})
			}
		}
	case "contains":
		for _, p := range rule.Patterns {
			if strings.Contains(content, p) {
				hits = append(hits, ScanHit{
					RuleName: rule.Name,
					Pattern:  p,
					Location: location,
				})
			}
		}
	case "not_contains":
		for _, p := range rule.Patterns {
			if !strings.Contains(content, p) {
				hits = append(hits, ScanHit{
					RuleName: rule.Name,
					Pattern:  p,
					Location: location,
				})
			}
		}
	}
	return hits
}

// templateData holds the variables available in reason/impact template strings.
type templateData struct {
	Protocol     string
	Service      string
	Verb         string
	ResourceType string
	ResourceName string
	Namespace    string
	Host         string
	Method       string
	Path         string
	ScanHits     []ScanHit
}

// expandTemplate renders a Go text/template string with operation fields.
func expandTemplate(tmplStr string, op *Operation, hits []ScanHit) string {
	if tmplStr == "" {
		return ""
	}
	t, err := template.New("").Parse(tmplStr)
	if err != nil {
		return tmplStr
	}
	data := templateData{
		Protocol:     op.Protocol,
		Service:      op.Service,
		Verb:         op.Verb,
		ResourceType: op.ResourceType,
		ResourceName: op.ResourceName,
		Namespace:    op.Namespace,
		Host:         op.Host,
		Method:       op.Method,
		Path:         op.Path,
		ScanHits:     hits,
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, data); err != nil {
		return tmplStr
	}
	return buf.String()
}
