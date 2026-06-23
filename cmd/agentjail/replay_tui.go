package main

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/LuD1161/agentjail/internal/store"
	"github.com/LuD1161/agentjail/internal/ui"
	"github.com/charmbracelet/bubbles/textinput"
	"github.com/charmbracelet/bubbles/viewport"
	tea "github.com/charmbracelet/bubbletea"
)

// --------------------------------------------------------------------------
// Message types
// --------------------------------------------------------------------------

type followTickMsg struct{}
type followResultMsg struct{ rows []store.DecisionRecord }
type followErrMsg struct{ err error }

// --------------------------------------------------------------------------
// Model
// --------------------------------------------------------------------------

type replayModel struct {
	store     store.ReadOnlyStore
	sessionID string
	allRows   []store.DecisionRecord
	filtered  []store.DecisionRecord
	lastID    int64

	ui *ui.UI

	viewport    viewport.Model
	cursor      int
	lineOffsets map[int]int
	expandedID  int64
	verbose     bool

	filterInput textinput.Model
	filtering   bool
	filterText  string

	allowCount int
	denyCount  int
	askCount   int

	follow      bool
	autoScroll  bool
	queryActive bool

	width  int
	height int

	err     error
	errTick int
}

func newReplayModel(rows []store.DecisionRecord, st store.ReadOnlyStore, sessionID string, u *ui.UI, verbose, follow bool) replayModel {
	ti := textinput.New()
	ti.Prompt = "/"
	ti.CharLimit = 256

	m := replayModel{
		store:       st,
		sessionID:   sessionID,
		allRows:     rows,
		ui:          u,
		verbose:     verbose,
		follow:      follow,
		autoScroll:  true,
		filterInput: ti,
		lineOffsets: make(map[int]int),
	}
	if len(rows) > 0 {
		m.lastID = rows[len(rows)-1].ID
	}
	m.filtered = filterRows(rows, "")
	m.computeStats()
	return m
}

// --------------------------------------------------------------------------
// Filter
// --------------------------------------------------------------------------

func filterRows(rows []store.DecisionRecord, filter string) []store.DecisionRecord {
	if filter == "" {
		cp := make([]store.DecisionRecord, len(rows))
		copy(cp, rows)
		return cp
	}
	lower := strings.ToLower(filter)
	var out []store.DecisionRecord
	for _, d := range rows {
		haystack := strings.ToLower(
			d.Ts.Local().Format("15:04:05") + " " +
				d.Action + " " +
				d.ToolName + " " +
				d.RuleID + " " +
				d.Summary,
		)
		if strings.Contains(haystack, lower) {
			out = append(out, d)
		}
	}
	return out
}

// --------------------------------------------------------------------------
// Stats
// --------------------------------------------------------------------------

func (m *replayModel) computeStats() {
	m.allowCount = 0
	m.denyCount = 0
	m.askCount = 0
	for _, d := range m.allRows {
		switch strings.ToLower(d.Action) {
		case "allow":
			m.allowCount++
		case "deny":
			m.denyCount++
		case "ask":
			m.askCount++
		}
	}
}

func (m *replayModel) duration() string {
	if len(m.allRows) < 2 {
		return "0s"
	}
	d := m.allRows[len(m.allRows)-1].Ts.Sub(m.allRows[0].Ts)
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	return fmt.Sprintf("%dm %ds", int(d.Minutes()), int(d.Seconds())%60)
}

// --------------------------------------------------------------------------
// Render
// --------------------------------------------------------------------------

func (m *replayModel) renderDocument() string {
	m.lineOffsets = make(map[int]int)
	var sb strings.Builder
	line := 0
	for i, d := range m.filtered {
		m.lineOffsets[i] = line
		isCursor := i == m.cursor
		row := m.ui.ReplayRow(
			d.Ts.Local().Format("15:04:05"),
			strings.ToUpper(d.Action),
			m.ui.Sanitize(d.ToolName),
			m.ui.Sanitize(d.RuleID),
			m.ui.Sanitize(d.Summary),
			isCursor,
		)
		sb.WriteString(row)
		line++

		if d.ID == m.expandedID && m.expandedID != 0 {
			if d.Reason != "" {
				sb.WriteString("\n" + m.ui.ReplayDetailLine("reason: "+m.ui.Sanitize(d.Reason)))
				line++
			}
			sb.WriteString("\n" + m.ui.ReplayDetailLine("rule: "+m.ui.Sanitize(d.RuleID)))
			line++
			if m.verbose && d.ToolInputRedacted != "" {
				sb.WriteString("\n" + m.ui.ReplayDetailLine("input: "+m.ui.Sanitize(d.ToolInputRedacted)))
				line++
			}
		}

		if i < len(m.filtered)-1 {
			sb.WriteString("\n")
		}
	}
	return sb.String()
}

func (m *replayModel) ensureCursorVisible() {
	if offset, ok := m.lineOffsets[m.cursor]; ok {
		if offset < m.viewport.YOffset {
			m.viewport.SetYOffset(offset)
		} else if offset >= m.viewport.YOffset+m.viewport.Height {
			m.viewport.SetYOffset(offset - m.viewport.Height + 1)
		}
	}
}

func (m *replayModel) clampCursor() {
	if m.cursor < 0 {
		m.cursor = 0
	}
	if len(m.filtered) > 0 && m.cursor >= len(m.filtered) {
		m.cursor = len(m.filtered) - 1
	}
}

// --------------------------------------------------------------------------
// tea.Model
// --------------------------------------------------------------------------

func (m replayModel) Init() tea.Cmd {
	if m.follow {
		return tea.Tick(500*time.Millisecond, func(_ time.Time) tea.Msg {
			return followTickMsg{}
		})
	}
	return nil
}

func (m replayModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	switch msg := msg.(type) {

	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		headerH := 2 // header + separator
		footerH := 3 // separator + stats + help
		m.viewport.Width = msg.Width
		m.viewport.Height = msg.Height - headerH - footerH
		if m.viewport.Height < 1 {
			m.viewport.Height = 1
		}
		m.viewport.SetContent(m.renderDocument())
		return m, nil

	case followTickMsg:
		if m.errTick > 0 {
			m.errTick--
			if m.errTick == 0 {
				m.err = nil
			}
		}
		if !m.follow || m.queryActive {
			return m, nil
		}
		m.queryActive = true
		lastID := m.lastID
		sid := m.sessionID
		st := m.store
		return m, func() tea.Msg {
			rows, err := st.ListDecisions(context.Background(), store.Filter{
				SessionID: sid,
				AfterID:   lastID,
				Limit:     1000,
			})
			if err != nil {
				return followErrMsg{err: err}
			}
			return followResultMsg{rows: rows}
		}

	case followResultMsg:
		m.queryActive = false
		if !m.follow {
			return m, nil
		}
		if len(msg.rows) > 0 {
			m.allRows = append(m.allRows, msg.rows...)
			m.lastID = msg.rows[len(msg.rows)-1].ID
			m.computeStats()
			m.filtered = filterRows(m.allRows, m.filterText)
			if m.autoScroll && len(m.filtered) > 0 {
				m.cursor = len(m.filtered) - 1
			}
			m.viewport.SetContent(m.renderDocument())
			if m.autoScroll {
				m.viewport.GotoBottom()
			}
		}
		return m, tea.Tick(500*time.Millisecond, func(_ time.Time) tea.Msg {
			return followTickMsg{}
		})

	case followErrMsg:
		m.queryActive = false
		if !m.follow {
			return m, nil
		}
		m.err = msg.err
		m.errTick = 6
		return m, tea.Tick(500*time.Millisecond, func(_ time.Time) tea.Msg {
			return followTickMsg{}
		})

	case tea.KeyMsg:
		if m.filtering {
			return m.updateFilterMode(msg)
		}
		return m.updateNormalMode(msg)
	}

	return m, nil
}

func (m replayModel) updateFilterMode(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.Type {
	case tea.KeyEsc:
		if m.filterInput.Value() != "" {
			m.filterInput.SetValue("")
			m.filterText = ""
			m.filtered = filterRows(m.allRows, "")
			m.cursor = 0
			m.expandedID = 0
			m.viewport.SetContent(m.renderDocument())
			m.viewport.GotoTop()
		} else {
			m.filtering = false
			m.filterInput.Blur()
		}
		return m, nil
	case tea.KeyEnter:
		m.filtering = false
		m.filterInput.Blur()
		return m, nil
	}
	var cmd tea.Cmd
	m.filterInput, cmd = m.filterInput.Update(msg)
	newFilter := m.filterInput.Value()
	if newFilter != m.filterText {
		m.filterText = newFilter
		m.filtered = filterRows(m.allRows, m.filterText)
		m.cursor = 0
		m.expandedID = 0
		m.viewport.SetContent(m.renderDocument())
		m.viewport.GotoTop()
	}
	return m, cmd
}

func (m replayModel) updateNormalMode(msg tea.KeyMsg) (tea.Model, tea.Cmd) {
	switch msg.String() {
	case "q", "ctrl+c":
		return m, tea.Quit

	case "j", "down":
		if m.cursor < len(m.filtered)-1 {
			m.cursor++
			m.autoScroll = m.cursor == len(m.filtered)-1
			m.viewport.SetContent(m.renderDocument())
			m.ensureCursorVisible()
		}
		return m, nil

	case "k", "up":
		if m.cursor > 0 {
			m.cursor--
			m.autoScroll = false
			m.viewport.SetContent(m.renderDocument())
			m.ensureCursorVisible()
		}
		return m, nil

	case "g":
		m.cursor = 0
		m.autoScroll = false
		m.viewport.SetContent(m.renderDocument())
		m.viewport.GotoTop()
		return m, nil

	case "G":
		if len(m.filtered) > 0 {
			m.cursor = len(m.filtered) - 1
		}
		m.autoScroll = true
		m.viewport.SetContent(m.renderDocument())
		m.viewport.GotoBottom()
		return m, nil

	case "d", "pgdown":
		half := m.viewport.Height / 2
		m.cursor += half
		m.clampCursor()
		m.autoScroll = m.cursor == len(m.filtered)-1
		m.viewport.SetContent(m.renderDocument())
		m.ensureCursorVisible()
		return m, nil

	case "u", "pgup":
		half := m.viewport.Height / 2
		m.cursor -= half
		m.clampCursor()
		m.autoScroll = false
		m.viewport.SetContent(m.renderDocument())
		m.ensureCursorVisible()
		return m, nil

	case "/":
		m.filtering = true
		m.filterInput.Focus()
		return m, textinput.Blink

	case "enter":
		if len(m.filtered) > 0 && m.cursor < len(m.filtered) {
			d := m.filtered[m.cursor]
			if m.expandedID == d.ID {
				m.expandedID = 0
			} else {
				m.expandedID = d.ID
			}
			m.viewport.SetContent(m.renderDocument())
			m.ensureCursorVisible()
		}
		return m, nil

	case "v":
		m.verbose = !m.verbose
		m.viewport.SetContent(m.renderDocument())
		m.ensureCursorVisible()
		return m, nil

	case "f":
		m.follow = !m.follow
		if m.follow {
			m.autoScroll = true
			return m, tea.Tick(500*time.Millisecond, func(_ time.Time) tea.Msg {
				return followTickMsg{}
			})
		}
		return m, nil

	case "esc":
		if m.expandedID != 0 {
			m.expandedID = 0
			m.viewport.SetContent(m.renderDocument())
		}
		return m, nil
	}
	return m, nil
}

func (m replayModel) View() string {
	if m.width == 0 {
		return "loading..."
	}

	title := fmt.Sprintf("agentjail replay %s (%d decisions)", shortSession(m.sessionID), len(m.allRows))
	header := m.ui.ReplayHeader(m.width)
	titleLine := m.ui.ReplayDetailLine(title)

	filterStr := m.filterText
	stats := m.ui.ReplayStatsBar(m.allowCount, m.denyCount, m.askCount, m.duration(), filterStr, m.follow, m.err, m.width)
	help := m.ui.ReplayHelpBar(m.filtering, m.width)

	var filterLine string
	if m.filtering {
		filterLine = m.filterInput.View()
		help = m.ui.ReplayHelpBar(true, m.width)
	}

	var sb strings.Builder
	sb.WriteString(titleLine + "\n")
	sb.WriteString(header + "\n")
	sb.WriteString(m.viewport.View() + "\n")
	sb.WriteString(stats + "\n")
	if filterLine != "" {
		sb.WriteString(filterLine + "\n")
	}
	sb.WriteString(help)

	return sb.String()
}
