package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/LuD1161/agentjail/agentpolicy/config"
	"github.com/LuD1161/agentjail/internal/store"
)

const (
	policyReportProtocolVersion uint32 = 1
	policySessionBreakdownLimit        = 2_000
	policyModuleLimit                  = 128
	policyModuleByteLimit              = 256 * 1024
	policySourceTotalByteLimit         = 1024 * 1024
)

type policyReportStore interface {
	CountPolicyMatches(ctx context.Context) ([]store.PolicyMatchCount, error)
	CountPolicyMatchesBySession(ctx context.Context, limit int) ([]store.PolicySessionMatch, error)
}

type policyReport struct {
	ProtocolVersion  uint32               `json:"protocol_version"`
	HistoryAvailable bool                 `json:"history_available"`
	Policies         []policyReportRule   `json:"policies"`
	Sources          []policyReportSource `json:"sources"`
	BreakdownLimited bool                 `json:"breakdown_limited"`
}

type policyReportSource struct {
	Filename string `json:"filename"`
	Rego     string `json:"rego"`
}

type policyReportRule struct {
	ID               string                   `json:"id"`
	Name             string                   `json:"name"`
	Description      string                   `json:"description"`
	Source           RuleSource               `json:"source"`
	SourceFile       string                   `json:"source_file"`
	Locked           bool                     `json:"locked"`
	MatchedCount     int64                    `json:"matched_count"`
	AgentCount       int64                    `json:"agent_count"`
	SessionCount     int64                    `json:"session_count"`
	BreakdownLimited bool                     `json:"breakdown_limited"`
	Examples         []policyReportExample    `json:"examples"`
	Evaluations      []policyReportEvaluation `json:"evaluations"`
}

type policyReportExample struct {
	Action string `json:"action"`
	Reason string `json:"reason"`
	Impact string `json:"impact"`
}

type policyReportEvaluation struct {
	Agent         string `json:"agent"`
	SessionID     string `json:"session_id"`
	SessionFolder string `json:"session_folder"`
	MatchedCount  int64  `json:"matched_count"`
}

type policyModule struct {
	filename string
	stem     string
	source   RuleSource
	rego     string
}

var (
	policyActionLiteral = regexp.MustCompile(`"action"\s*:\s*("(?:\\.|[^"\\])*")`)
	policyReasonLiteral = regexp.MustCompile(`"reason"\s*:\s*("(?:\\.|[^"\\])*")`)
	policyImpactLiteral = regexp.MustCompile(`"impact"\s*:\s*("(?:\\.|[^"\\])*")`)
)

func printPolicyReportJSONOutput(w io.Writer, home string) error {
	var history policyReportStore
	dbPath := filepath.Join(home, ".agentjail", "agentjail.db")
	readOnly, err := store.OpenReadOnly(dbPath)
	if err == nil {
		defer readOnly.Close()
		matchReader, ok := readOnly.(policyReportStore)
		if !ok {
			return fmt.Errorf("policy match projection unavailable")
		}
		history = matchReader
	} else if !os.IsNotExist(rootCause(err)) {
		return err
	}

	report, err := collectPolicyReport(context.Background(), home, history)
	if err != nil {
		return err
	}
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return encoder.Encode(report)
}

func collectPolicyReport(ctx context.Context, home string, history policyReportStore) (policyReport, error) {
	policyPath := filepath.Join(home, ".agentjail", "policy.yaml")
	cfg, err := config.LoadOrDefault(policyPath)
	if err != nil {
		return policyReport{}, fmt.Errorf("load policy config: %w", err)
	}
	modules, err := readActivePolicyModules(filepath.Join(home, ".agentjail", "rules"))
	if err != nil {
		return policyReport{}, err
	}

	totals := map[string]store.PolicyMatchCount{}
	breakdowns := map[string][]store.PolicySessionMatch{}
	report := policyReport{
		ProtocolVersion:  policyReportProtocolVersion,
		HistoryAvailable: history != nil,
		Policies:         []policyReportRule{},
		Sources:          make([]policyReportSource, 0, len(modules)),
	}
	for _, module := range modules {
		report.Sources = append(report.Sources, policyReportSource{Filename: module.filename, Rego: module.rego})
	}
	if history != nil {
		rows, err := history.CountPolicyMatches(ctx)
		if err != nil {
			return policyReport{}, err
		}
		for _, row := range rows {
			totals[row.RuleID] = row
		}
		rowsBySession, err := history.CountPolicyMatchesBySession(ctx, policySessionBreakdownLimit)
		if err != nil {
			return policyReport{}, err
		}
		for _, row := range rowsBySession {
			breakdowns[row.RuleID] = append(breakdowns[row.RuleID], row)
		}
	}

	locked := LockedRuleIDs()
	seen := map[string]bool{}
	for _, module := range modules {
		for _, id := range extractRuleIDs(module.rego) {
			if seen[id] || (!locked[id] && isDisabledByConfig(cfg, id)) {
				continue
			}
			seen[id] = true
			total := totals[id]
			evaluations := make([]policyReportEvaluation, 0, len(breakdowns[id]))
			var attributed int64
			for _, row := range breakdowns[id] {
				attributed += row.Count
				evaluations = append(evaluations, policyReportEvaluation{
					Agent: boundedPolicyText(row.Agent, 64), SessionID: boundedPolicyText(row.SessionID, 128),
					SessionFolder: policySessionFolder(row.CWD), MatchedCount: row.Count,
				})
			}
			limited := attributed < total.Count
			report.BreakdownLimited = report.BreakdownLimited || limited
			examples := extractPolicyExamples(module.rego, id)
			description := policyDescription(id, examples)
			report.Policies = append(report.Policies, policyReportRule{
				ID: id, Name: policyDisplayName(id), Description: description,
				Source: module.source, SourceFile: module.filename, Locked: locked[id],
				MatchedCount: total.Count, AgentCount: total.AgentCount, SessionCount: total.SessionCount,
				BreakdownLimited: limited, Examples: examples, Evaluations: evaluations,
			})
		}
	}
	sort.Slice(report.Policies, func(i, j int) bool { return report.Policies[i].ID < report.Policies[j].ID })
	return report, nil
}

func readActivePolicyModules(dir string) ([]policyModule, error) {
	entries, err := os.ReadDir(dir)
	if os.IsNotExist(err) {
		return []policyModule{}, nil
	}
	if err != nil {
		return nil, fmt.Errorf("read policy modules: %w", err)
	}
	if len(entries) > policyModuleLimit {
		return nil, fmt.Errorf("policy module count exceeds %d", policyModuleLimit)
	}

	core := make(map[string]bool)
	for _, name := range coreRuleNames() {
		core[name] = true
	}
	library := make(map[string]bool)
	for _, name := range libraryRuleNames() {
		library[name] = true
	}
	modules := make([]policyModule, 0, len(entries))
	totalBytes := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".rego") || strings.HasSuffix(entry.Name(), "_test.rego") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		file, err := os.Open(path)
		if err != nil {
			return nil, fmt.Errorf("open policy module %s: %w", entry.Name(), err)
		}
		data, readErr := io.ReadAll(io.LimitReader(file, policyModuleByteLimit+1))
		closeErr := file.Close()
		if readErr != nil {
			return nil, fmt.Errorf("read policy module %s: %w", entry.Name(), readErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("close policy module %s: %w", entry.Name(), closeErr)
		}
		if len(data) > policyModuleByteLimit {
			return nil, fmt.Errorf("policy module %s exceeds %d bytes", entry.Name(), policyModuleByteLimit)
		}
		totalBytes += len(data)
		if totalBytes > policySourceTotalByteLimit {
			return nil, fmt.Errorf("policy sources exceed %d bytes", policySourceTotalByteLimit)
		}
		stem := strings.TrimSuffix(entry.Name(), ".rego")
		source := RuleSourceCustom
		if core[stem] {
			source = RuleSourceCore
		} else if library[stem] {
			source = RuleSourceLibrary
		}
		modules = append(modules, policyModule{filename: entry.Name(), stem: stem, source: source, rego: string(data)})
	}
	sort.Slice(modules, func(i, j int) bool { return modules[i].filename < modules[j].filename })
	return modules, nil
}

func policyDescription(id string, examples []policyReportExample) string {
	if entry, ok := RegistryByID(id); ok && entry.Description != "" {
		return entry.Description
	}
	for _, example := range examples {
		if example.Reason != "" {
			return example.Reason
		}
		if example.Impact != "" {
			return example.Impact
		}
	}
	return "Applies the " + policyDisplayName(id) + " policy decision."
}

func policyDisplayName(id string) string {
	name := id
	if slash := strings.LastIndexByte(id, '/'); slash >= 0 && slash+1 < len(id) {
		name = id[slash+1:]
	}
	parts := strings.FieldsFunc(name, func(r rune) bool { return r == '-' || r == '_' })
	for i := range parts {
		parts[i] = strings.ToUpper(parts[i][:1]) + parts[i][1:]
	}
	return strings.Join(parts, " ")
}

func extractPolicyExamples(source, ruleID string) []policyReportExample {
	lines := make([]string, 0)
	scanner := bufio.NewScanner(strings.NewReader(source))
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	needle := `"rule_id": "` + ruleID + `"`
	seen := map[string]bool{}
	examples := make([]policyReportExample, 0, 3)
	for index, line := range lines {
		if !strings.Contains(line, needle) {
			continue
		}
		start := index - 12
		if start < 0 {
			start = 0
		}
		end := index + 13
		if end > len(lines) {
			end = len(lines)
		}
		block := strings.Join(lines[start:end], "\n")
		example := policyReportExample{
			Action: extractPolicyLiteral(policyActionLiteral, block),
			Reason: extractPolicyLiteral(policyReasonLiteral, block),
			Impact: extractPolicyLiteral(policyImpactLiteral, block),
		}
		key := example.Action + "\x00" + example.Reason + "\x00" + example.Impact
		if key == "\x00\x00" || seen[key] {
			continue
		}
		seen[key] = true
		examples = append(examples, example)
		if len(examples) == 3 {
			break
		}
	}
	return examples
}

func extractPolicyLiteral(pattern *regexp.Regexp, block string) string {
	match := pattern.FindStringSubmatch(block)
	if len(match) != 2 {
		return ""
	}
	value, err := strconv.Unquote(match[1])
	if err != nil {
		return ""
	}
	return value
}

func policySessionFolder(cwd string) string {
	if cwd == "" {
		return "Unknown folder"
	}
	clean := filepath.Clean(cwd)
	base := filepath.Base(clean)
	if base == "." || base == string(filepath.Separator) || base == "" {
		return clean
	}
	return boundedPolicyText("…/"+base, 96)
}

func boundedPolicyText(value string, maxRunes int) string {
	runes := []rune(value)
	if len(runes) <= maxRunes {
		return value
	}
	return string(runes[:maxRunes-1]) + "…"
}

func rootCause(err error) error {
	for {
		unwrapped, ok := err.(interface{ Unwrap() error })
		if !ok || unwrapped.Unwrap() == nil {
			return err
		}
		err = unwrapped.Unwrap()
	}
}
