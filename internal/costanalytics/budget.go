package costanalytics

import (
	"fmt"
	"sort"
	"time"
)

type BudgetLevel string
type BudgetScope string

const (
	BudgetWarning     BudgetLevel = "warning"
	BudgetExceeded    BudgetLevel = "exceeded"
	BudgetScopeGlobal BudgetScope = "global"
)

// BudgetAlert represents a single budget warning or exceeded alert.
type BudgetAlert struct {
	Level   BudgetLevel `json:"level"`
	Scope   BudgetScope `json:"scope"`
	Budget  float64     `json:"budget"`  // configured budget in USD
	Spent   float64     `json:"spent"`   // amount spent in USD
	Percent float64     `json:"percent"` // spent/budget * 100
	Message string      `json:"message"`
}

// BudgetStatus holds all budget alerts for the current period.
type BudgetStatus struct {
	Alerts []BudgetAlert `json:"alerts"`
}

// CheckBudget evaluates today's spending against enabled global and project limits.
func CheckBudget(dailyBudget float64, projectBudgets map[string]float64, alertThreshold float64, sessions []SessionCost) BudgetStatus {
	return checkBudgetAt(time.Now(), dailyBudget, projectBudgets, alertThreshold, sessions)
}

func checkBudgetAt(now time.Time, dailyBudget float64, projectBudgets map[string]float64, alertThreshold float64, sessions []SessionCost) BudgetStatus {
	status := BudgetStatus{Alerts: []BudgetAlert{}}

	if dailyBudget <= 0 && len(projectBudgets) == 0 {
		return status
	}

	today := todaySessions(now, sessions)

	if dailyBudget > 0 {
		var totalSpent float64
		for _, s := range today {
			totalSpent += s.CostUSD
		}
		pct := totalSpent / dailyBudget * 100
		if totalSpent >= dailyBudget {
			status.Alerts = append(status.Alerts, BudgetAlert{
				Level:   BudgetExceeded,
				Scope:   BudgetScopeGlobal,
				Budget:  dailyBudget,
				Spent:   totalSpent,
				Percent: pct,
				Message: fmt.Sprintf("Global daily budget exceeded ($%.2f of $%.2f)", totalSpent, dailyBudget),
			})
		} else if alertThreshold > 0 && totalSpent >= alertThreshold*dailyBudget {
			status.Alerts = append(status.Alerts, BudgetAlert{
				Level:   BudgetWarning,
				Scope:   BudgetScopeGlobal,
				Budget:  dailyBudget,
				Spent:   totalSpent,
				Percent: pct,
				Message: fmt.Sprintf("Global daily budget %.0f%% used ($%.2f of $%.2f)", pct, totalSpent, dailyBudget),
			})
		}
	}

	if len(projectBudgets) > 0 {
		projectSpend := make(map[Project]float64)
		for _, s := range today {
			norm := normalizeProject(s.Project)
			if norm == "" {
				norm = "(unknown)"
			}
			projectSpend[norm] += s.CostUSD
		}

		projects := make([]string, 0, len(projectBudgets))
		for project := range projectBudgets {
			projects = append(projects, project)
		}
		sort.Strings(projects)
		for _, proj := range projects {
			budget := projectBudgets[proj]
			if budget <= 0 {
				continue
			}
			spent := projectSpend[Project(proj)]
			if spent == 0 {
				continue
			}
			pct := spent / budget * 100
			if spent >= budget {
				status.Alerts = append(status.Alerts, BudgetAlert{
					Level:   BudgetExceeded,
					Scope:   BudgetScope(proj),
					Budget:  budget,
					Spent:   spent,
					Percent: pct,
					Message: fmt.Sprintf("%s exceeded daily budget ($%.2f of $%.2f)", proj, spent, budget),
				})
			} else if alertThreshold > 0 && spent >= alertThreshold*budget {
				status.Alerts = append(status.Alerts, BudgetAlert{
					Level:   BudgetWarning,
					Scope:   BudgetScope(proj),
					Budget:  budget,
					Spent:   spent,
					Percent: pct,
					Message: fmt.Sprintf("%s daily budget %.0f%% used ($%.2f of $%.2f)", proj, pct, spent, budget),
				})
			}
		}
	}

	return status
}

// todaySessions filters sessions to those started on or after midnight UTC today.
func todaySessions(now time.Time, sessions []SessionCost) []SessionCost {
	now = now.UTC()
	midnight := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, time.UTC)
	var out []SessionCost
	for _, s := range sessions {
		if !s.StartedAt.Before(midnight) {
			out = append(out, s)
		}
	}
	return out
}
