package costanalytics

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

func CollectAll(since time.Time) ([]SessionCost, []error) {
	var all []SessionCost
	var errs []error

	if _, err := GetPricingProvider(); err != nil {
		errs = append(errs, err)
	}

	ccReader := NewClaudeCodeReader()
	if sessions, err := ccReader.ReadSessions(since); err != nil {
		all = append(all, sessions...)
		errs = append(errs, err)
	} else {
		all = append(all, sessions...)
	}

	codexReader := NewCodexReader()
	if sessions, err := codexReader.ReadSessions(since); err != nil {
		all = append(all, sessions...)
		errs = append(errs, err)
	} else {
		all = append(all, sessions...)
	}

	ocReader, err := NewOpenCodeReader(DefaultOpenCodeDBPath())
	if err != nil {
		if !errors.Is(err, os.ErrNotExist) {
			errs = append(errs, err)
		}
	} else {
		sessions, err := ocReader.ReadSessions(since)
		closeErr := ocReader.Close()
		if err != nil {
			errs = append(errs, err)
		} else {
			all = append(all, sessions...)
		}
		if closeErr != nil {
			errs = append(errs, closeErr)
		}
	}
	errs = append(errs, missingPricingErrors(all)...)
	errs = append(errs, incompleteRequestPricingErrors(all)...)

	return all, errs
}

func incompleteRequestPricingErrors(sessions []SessionCost) []error {
	models := make(map[Model]struct{})
	for _, session := range sessions {
		if session.PricingMode == PricingModeBaseEstimate && requiresRequestPricing(session.Model) {
			models[session.Model] = struct{}{}
		}
	}
	ordered := make([]Model, 0, len(models))
	for model := range models {
		ordered = append(ordered, model)
	}
	sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
	errs := make([]error, 0, len(ordered))
	for _, model := range ordered {
		errs = append(errs, fmt.Errorf("model %q has sessions without complete per-request usage; base rates used where long-context tier could not be reconstructed", model))
	}
	return errs
}

func missingPricingErrors(sessions []SessionCost) []error {
	missing := make(map[Model]struct{})
	for _, session := range sessions {
		model := session.Model
		hasTokenUsage := session.InputTokens != 0 || session.OutputTokens != 0 || session.CacheRead != 0 || session.CacheWrite != 0
		if !hasTokenUsage ||
			strings.HasPrefix(string(model), "<") || strings.HasPrefix(string(model), "(") ||
			HasPricing(model) {
			continue
		}
		missing[model] = struct{}{}
	}
	models := make([]Model, 0, len(missing))
	for model := range missing {
		models = append(models, model)
	}
	sort.Slice(models, func(i, j int) bool { return models[i] < models[j] })
	errs := make([]error, 0, len(models))
	for _, model := range models {
		errs = append(errs, fmt.Errorf("model pricing unavailable for %q; token usage is included but estimated cost is $0", model))
	}
	return errs
}

func Aggregate(sessions []SessionCost, period Period) CostReport {
	report := CostReport{Period: period}

	if len(sessions) == 0 {
		report.ByProject = []ProjectSummary{}
		report.ByModel = []ModelSummary{}
		return report
	}

	var totalInput, totalOutput, totalCacheRead int64
	projectCost := make(map[Project]*ProjectSummary)
	modelCost := make(map[Model]*ModelSummary)
	allSessions := make(map[string]struct{})
	projectSessions := make(map[Project]map[string]struct{})
	modelSessions := make(map[Model]map[string]struct{})

	for i, s := range sessions {
		key := sessionKey(s, i)
		allSessions[key] = struct{}{}
		report.TotalCost += s.CostUSD
		totalInput += s.InputTokens
		totalOutput += s.OutputTokens
		totalCacheRead += s.CacheRead

		proj := normalizeProject(s.Project)
		if proj == "" {
			proj = Project("(unknown)")
		}
		ps, ok := projectCost[proj]
		if !ok {
			ps = &ProjectSummary{Project: proj}
			projectCost[proj] = ps
		}
		ps.CostUSD += s.CostUSD
		if projectSessions[proj] == nil {
			projectSessions[proj] = make(map[string]struct{})
		}
		projectSessions[proj][key] = struct{}{}

		model := s.Model
		if model == "" {
			model = Model("(unknown)")
		}
		ms, ok := modelCost[model]
		if !ok {
			ms = &ModelSummary{Model: model}
			modelCost[model] = ms
		}
		ms.CostUSD += s.CostUSD
		if modelSessions[model] == nil {
			modelSessions[model] = make(map[string]struct{})
		}
		modelSessions[model][key] = struct{}{}
		ms.InputTokens += s.InputTokens
		ms.OutputTokens += s.OutputTokens
		ms.CacheRead += s.CacheRead
		ms.CacheWrite += s.CacheWrite
		ms.CacheWrite5m += s.CacheWrite5m
		ms.CacheWrite1h += s.CacheWrite1h
		ms.BaseEstimate = ms.BaseEstimate || s.PricingMode == PricingModeBaseEstimate
	}

	for _, ps := range projectCost {
		ps.SessionCount = len(projectSessions[ps.Project])
		if report.TotalCost > 0 {
			ps.Percent = ps.CostUSD / report.TotalCost * 100
		}
		report.ByProject = append(report.ByProject, *ps)
	}
	sort.Slice(report.ByProject, func(i, j int) bool {
		if report.ByProject[i].CostUSD == report.ByProject[j].CostUSD {
			return report.ByProject[i].Project < report.ByProject[j].Project
		}
		return report.ByProject[i].CostUSD > report.ByProject[j].CostUSD
	})

	for _, ms := range modelCost {
		ms.SessionCount = len(modelSessions[ms.Model])
		if report.TotalCost > 0 {
			ms.Percent = ms.CostUSD / report.TotalCost * 100
		}
		report.ByModel = append(report.ByModel, *ms)
	}
	sort.Slice(report.ByModel, func(i, j int) bool {
		if report.ByModel[i].CostUSD == report.ByModel[j].CostUSD {
			return report.ByModel[i].Model < report.ByModel[j].Model
		}
		return report.ByModel[i].CostUSD > report.ByModel[j].CostUSD
	})

	totalReadable := totalInput + totalCacheRead
	if totalReadable > 0 {
		report.CacheHitRate = float64(totalCacheRead) / float64(totalReadable) * 100
	}

	report.SessionCount = len(allSessions)
	n := int64(report.SessionCount)
	report.AvgCost = report.TotalCost / float64(n)
	report.AvgInputTok = totalInput / n
	report.AvgOutputTok = totalOutput / n

	return report
}

func sessionKey(session SessionCost, index int) string {
	if session.SessionID == "" {
		return fmt.Sprintf("record:%d", index)
	}
	return string(session.Source) + "\x00" + string(session.SessionID)
}

func FilterByProject(sessions []SessionCost, project string) []SessionCost {
	if project == "" {
		return sessions
	}
	abs, err := filepath.Abs(project)
	if err != nil {
		abs = project
	}
	var filtered []SessionCost
	for _, s := range sessions {
		projectPath := string(s.Project)
		if projectPath == abs || strings.HasPrefix(projectPath, abs+string(filepath.Separator)) || projectPath == project {
			filtered = append(filtered, s)
		}
	}
	return filtered
}

func normalizeProject(dir Project) Project {
	if dir == "" {
		return ""
	}
	home, err := os.UserHomeDir()
	if err != nil {
		return dir
	}
	rel, err := filepath.Rel(home, string(dir))
	if err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		if rel == "." {
			return Project("~")
		}
		return Project(filepath.Join("~", rel))
	}
	return dir
}
