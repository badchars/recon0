package pipeline

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

// State represents the pipeline execution state, persisted as JSON.
type State struct {
	mu   sync.Mutex
	path string

	Version      int                    `json:"version"`
	JobID        string                 `json:"job_id"`
	Program      string                 `json:"program"`
	Domain       string                 `json:"domain"`
	Domains      []string               `json:"domains,omitempty"`
	StartedAt    string                 `json:"started_at"`
	FinishedAt   *string                `json:"finished_at"`
	Status       string                 `json:"status"`
	CurrentStage string                 `json:"current_stage"`
	ConfigHash   string                 `json:"config_hash,omitempty"`
	Resources    *StateResources        `json:"resources,omitempty"`
	Progress     *ProgressInfo          `json:"progress,omitempty"`
	Stages       map[string]*StageState `json:"stages"`
	Errors       []StateError           `json:"errors"`
	Summary      map[string]int         `json:"summary"`
}

// ProgressInfo holds real-time progress info for the active provider.
type ProgressInfo struct {
	StagesDone           int    `json:"stages_done"`
	StagesTotal          int    `json:"stages_total"`
	CurrentProvider      string `json:"current_provider,omitempty"`
	CurrentProviderLines int    `json:"current_provider_lines,omitempty"`
	CurrentProviderSecs  int    `json:"current_provider_elapsed_s,omitempty"`
}

// StateResources records detected system resources.
type StateResources struct {
	Cores        int `json:"cores"`
	RamGB        int `json:"ram_gb"`
	ThreadsFull  int `json:"threads_full"`
	ThreadsHeavy int `json:"threads_heavy"`
	ThreadsLight int `json:"threads_light"`
}

// StageState holds the state of a single pipeline stage.
type StageState struct {
	Status     string                    `json:"status"`
	StartedAt  string                    `json:"started_at,omitempty"`
	FinishedAt string                    `json:"finished_at,omitempty"`
	DurationS  int                       `json:"duration_s,omitempty"`
	Providers  map[string]*ProviderState `json:"providers,omitempty"`
	Stats      map[string]int            `json:"stats,omitempty"`
}

// ProviderState holds the state of a single provider execution.
type ProviderState struct {
	Status     string `json:"status"`
	Count      int    `json:"count"`
	DurationS  int    `json:"duration_s"`
	OutputFile string `json:"output_file,omitempty"`
}

// StateError records an error that occurred during the pipeline.
type StateError struct {
	Time     string `json:"time"`
	Stage    string `json:"stage"`
	Provider string `json:"provider"`
	Error    string `json:"error"`
	Fatal    bool   `json:"fatal"`
}

// NewState creates a fresh pipeline state.
func NewState(path, jobID, program string, domains []string) *State {
	domain := ""
	if len(domains) > 0 {
		domain = domains[0]
	}
	return &State{
		path:      path,
		Version:   1,
		JobID:     jobID,
		Program:   program,
		Domain:    domain,
		Domains:   domains,
		StartedAt: nowUTC(),
		Status:    "running",
		Stages:    make(map[string]*StageState),
		Errors:    []StateError{},
		Summary:   make(map[string]int),
	}
}

// LoadState reads an existing state file for resume.
func LoadState(path string) (*State, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read state: %w", err)
	}
	var s State
	if err := json.Unmarshal(data, &s); err != nil {
		return nil, fmt.Errorf("parse state: %w", err)
	}
	s.path = path
	if s.Stages == nil {
		s.Stages = make(map[string]*StageState)
	}
	if s.Errors == nil {
		s.Errors = []StateError{}
	}
	if s.Summary == nil {
		s.Summary = make(map[string]int)
	}
	return &s, nil
}

// StageDone returns true if the named stage has status "done".
func (s *State) StageDone(name string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	st, ok := s.Stages[name]
	return ok && st.Status == "done"
}

// ResetStage clears the state for a stage so it can be re-run.
func (s *State) ResetStage(name string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.Stages, name)
	s.save()
}

// SetResources records the detected resources.
func (s *State) SetResources(cores, ramGB, threadsFull, threadsHeavy, threadsLight int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Resources = &StateResources{
		Cores:        cores,
		RamGB:        ramGB,
		ThreadsFull:  threadsFull,
		ThreadsHeavy: threadsHeavy,
		ThreadsLight: threadsLight,
	}
	s.save()
}

// UpdateStage updates a stage's status and optional stats.
func (s *State) UpdateStage(name, status string, stats map[string]int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	st, ok := s.Stages[name]
	if !ok {
		st = &StageState{
			Providers: make(map[string]*ProviderState),
			Stats:     make(map[string]int),
		}
		s.Stages[name] = st
	}

	st.Status = status
	s.CurrentStage = name

	if status == "running" {
		st.StartedAt = nowUTC()
	}
	if status == "done" {
		st.FinishedAt = nowUTC()
		if st.StartedAt != "" {
			if start, err := time.Parse(time.RFC3339, st.StartedAt); err == nil {
				st.DurationS = int(time.Since(start).Seconds())
			}
		}
	}

	if stats != nil {
		for k, v := range stats {
			st.Stats[k] = v
			s.Summary[k] = v
		}
	}

	s.save()
}

// UpdateProvider updates a provider's execution state within a stage.
func (s *State) UpdateProvider(stage, name, status string, count int, durationS int, outputFile string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	st, ok := s.Stages[stage]
	if !ok {
		st = &StageState{
			Providers: make(map[string]*ProviderState),
			Stats:     make(map[string]int),
		}
		s.Stages[stage] = st
	}

	st.Providers[name] = &ProviderState{
		Status:     status,
		Count:      count,
		DurationS:  durationS,
		OutputFile: outputFile,
	}

	s.save()
}

// UpdateProgress updates real-time progress info.
func (s *State) UpdateProgress(stagesDone, stagesTotal int, provider string, lines, elapsedS int) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Progress = &ProgressInfo{
		StagesDone:           stagesDone,
		StagesTotal:          stagesTotal,
		CurrentProvider:      provider,
		CurrentProviderLines: lines,
		CurrentProviderSecs:  elapsedS,
	}

	s.save()
}

// ClearProgress clears the progress info (called when provider finishes).
func (s *State) ClearProgress() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Progress = nil
	s.save()
}

// AddError records a pipeline error.
func (s *State) AddError(stage, provider, errMsg string, fatal bool) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Errors = append(s.Errors, StateError{
		Time:     nowUTC(),
		Stage:    stage,
		Provider: provider,
		Error:    errMsg,
		Fatal:    fatal,
	})

	s.save()
}

// Finish marks the pipeline as complete.
func (s *State) Finish(status string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.Status = status
	t := nowUTC()
	s.FinishedAt = &t

	s.save()
}

// Query returns a human-readable status summary.
func (s *State) Query() string {
	s.mu.Lock()
	defer s.mu.Unlock()

	var b strings.Builder

	if len(s.Domains) > 1 {
		fmt.Fprintf(&b, "recon0 — %s (%d domains) — %s\n", s.Program, len(s.Domains), s.Status)
	} else {
		fmt.Fprintf(&b, "recon0 — %s (%s) — %s\n", s.Program, s.Domain, s.Status)
	}
	fmt.Fprintf(&b, "Started: %s\n", s.StartedAt)
	if s.Resources != nil {
		fmt.Fprintf(&b, "Resources: %d cores, %dGB RAM\n", s.Resources.Cores, s.Resources.RamGB)
	}
	b.WriteString("\n")

	stageOrder := []string{"enum", "resolve", "probe", "crawl", "portscan", "discover", "analyze", "collect", "vuln"}
	for i, name := range stageOrder {
		st, ok := s.Stages[name]
		if !ok {
			fmt.Fprintf(&b, "  %d  %-12s pending\n", i+1, name)
			continue
		}

		provParts := []string{}
		for pName, p := range st.Providers {
			provParts = append(provParts, fmt.Sprintf("%s=%d", pName, p.Count))
		}
		provStr := strings.Join(provParts, ", ")

		statParts := []string{}
		for k, v := range st.Stats {
			statParts = append(statParts, fmt.Sprintf("%s: %d", k, v))
		}
		statStr := strings.Join(statParts, ", ")

		durStr := ""
		if st.DurationS > 0 {
			durStr = formatDuration(st.DurationS)
		}

		fmt.Fprintf(&b, "  %d  %-12s %-10s %-30s %-25s %s\n",
			i+1, name, st.Status, provStr, statStr, durStr)
	}

	if len(s.Errors) > 0 {
		fmt.Fprintf(&b, "\nErrors: %d\n", len(s.Errors))
		for _, e := range s.Errors {
			fmt.Fprintf(&b, "  ! %s/%s: %s\n", e.Stage, e.Provider, e.Error)
		}
	}

	return b.String()
}

// save writes the state to disk atomically (temp file + rename).
func (s *State) save() {
	if s.path == "" {
		return
	}

	data, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return
	}

	tmp := s.path + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return
	}

	dir := filepath.Dir(s.path)
	os.MkdirAll(dir, 0755)
	os.Rename(tmp, s.path)
}

func nowUTC() string {
	return time.Now().UTC().Format(time.RFC3339)
}

func formatDuration(seconds int) string {
	if seconds < 60 {
		return fmt.Sprintf("%ds", seconds)
	}
	if seconds < 3600 {
		return fmt.Sprintf("%dm%ds", seconds/60, seconds%60)
	}
	return fmt.Sprintf("%dh%dm", seconds/3600, (seconds%3600)/60)
}
