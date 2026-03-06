package api

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/badchars/recon0/internal/log"
	"github.com/badchars/recon0/internal/pipeline"
	"github.com/badchars/recon0/internal/queue"
)

// Server holds the HTTP API state.
type Server struct {
	queue     *queue.Queue
	state     *pipeline.State // current running scan state (nil if idle)
	outputDir string
	logger    *log.Logger
	mux       *http.ServeMux
}

// New creates an API server.
func New(q *queue.Queue, outputDir string, logger *log.Logger) *Server {
	s := &Server{
		queue:     q,
		outputDir: outputDir,
		logger:    logger,
		mux:       http.NewServeMux(),
	}
	s.routes()
	return s
}

// SetState sets the current active scan state (called when a scan starts/stops).
func (s *Server) SetState(state *pipeline.State) {
	s.state = state
}

// Start starts the HTTP server (blocking).
func (s *Server) Start(listen string, port int) error {
	addr := fmt.Sprintf("%s:%d", listen, port)
	s.logger.Infof("Status API listening on %s", addr)
	return http.ListenAndServe(addr, s.withCORS(s.mux))
}

func (s *Server) routes() {
	s.mux.HandleFunc("/api/health", s.handleHealth)
	s.mux.HandleFunc("/api/status", s.handleStatus)
	s.mux.HandleFunc("/api/status/", s.handleStatusByID)
	s.mux.HandleFunc("/api/runs", s.handleRuns)
	s.mux.HandleFunc("/api/logs/", s.handleLogs)
	s.mux.HandleFunc("/api/scan", s.handleScan)
	s.mux.HandleFunc("/api/queue", s.handleQueue)
	s.mux.HandleFunc("/api/queue/", s.handleQueueDelete)
}

// ── Handlers ──

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"ok": true})
}

func (s *Server) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Return active scan state if available
	if s.state != nil {
		writeJSON(w, http.StatusOK, s.state)
		return
	}

	// Fall back to most recent run
	state := s.loadLatestState()
	if state == nil {
		writeJSON(w, http.StatusOK, map[string]any{"status": "idle", "message": "no active scan"})
		return
	}
	writeJSON(w, http.StatusOK, state)
}

func (s *Server) handleStatusByID(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	runID := strings.TrimPrefix(r.URL.Path, "/api/status/")
	if runID == "" {
		http.Error(w, "run_id required", http.StatusBadRequest)
		return
	}

	stateFile := filepath.Join(s.outputDir, runID, "state.json")
	state, err := pipeline.LoadState(stateFile)
	if err != nil {
		http.Error(w, "run not found", http.StatusNotFound)
		return
	}
	writeJSON(w, http.StatusOK, state)
}

func (s *Server) handleRuns(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	entries, err := os.ReadDir(s.outputDir)
	if err != nil {
		writeJSON(w, http.StatusOK, []any{})
		return
	}

	type runSummary struct {
		ID       string `json:"id"`
		Program  string `json:"program"`
		Domain   string `json:"domain"`
		Status   string `json:"status"`
		Started  string `json:"started_at"`
		Finished string `json:"finished_at,omitempty"`
	}

	var runs []runSummary
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		stateFile := filepath.Join(s.outputDir, e.Name(), "state.json")
		state, err := pipeline.LoadState(stateFile)
		if err != nil {
			continue
		}
		rs := runSummary{
			ID:      state.JobID,
			Program: state.Program,
			Domain:  state.Domain,
			Status:  state.Status,
			Started: state.StartedAt,
		}
		if state.FinishedAt != nil {
			rs.Finished = *state.FinishedAt
		}
		runs = append(runs, rs)
	}

	writeJSON(w, http.StatusOK, runs)
}

func (s *Server) handleLogs(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	runID := strings.TrimPrefix(r.URL.Path, "/api/logs/")
	if runID == "" {
		http.Error(w, "run_id required", http.StatusBadRequest)
		return
	}

	lines := 100
	if v := r.URL.Query().Get("lines"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			lines = n
		}
	}

	logFile := filepath.Join(s.outputDir, runID, "logs", "pipeline.log")
	tail, err := tailFile(logFile, lines)
	if err != nil {
		http.Error(w, "log file not found", http.StatusNotFound)
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"run_id": runID,
		"lines":  tail,
	})
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	var req struct {
		Domain  string `json:"domain"`
		Program string `json:"program"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON", http.StatusBadRequest)
		return
	}
	if req.Domain == "" {
		http.Error(w, "domain is required", http.StatusBadRequest)
		return
	}
	if req.Program == "" {
		req.Program = req.Domain
	}

	job := s.queue.Add(req.Domain, req.Program)
	pos := s.queue.Position(job.ID)

	writeJSON(w, http.StatusAccepted, map[string]any{
		"queue_id": job.ID,
		"position": pos,
		"domain":   job.Domain,
		"program":  job.Program,
		"status":   job.Status,
	})
}

func (s *Server) handleQueue(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	jobs := s.queue.List()
	current := s.queue.Current()
	pending := s.queue.PendingCount()

	writeJSON(w, http.StatusOK, map[string]any{
		"current": current,
		"pending": pending,
		"jobs":    jobs,
	})
}

func (s *Server) handleQueueDelete(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodDelete {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	id := strings.TrimPrefix(r.URL.Path, "/api/queue/")
	if id == "" {
		http.Error(w, "id required", http.StatusBadRequest)
		return
	}

	if s.queue.Remove(id) {
		writeJSON(w, http.StatusOK, map[string]any{"removed": id})
	} else {
		http.Error(w, "job not found or already running", http.StatusNotFound)
	}
}

// ── Helpers ──

func (s *Server) loadLatestState() *pipeline.State {
	entries, err := os.ReadDir(s.outputDir)
	if err != nil || len(entries) == 0 {
		return nil
	}
	for i := len(entries) - 1; i >= 0; i-- {
		if !entries[i].IsDir() {
			continue
		}
		stateFile := filepath.Join(s.outputDir, entries[i].Name(), "state.json")
		state, err := pipeline.LoadState(stateFile)
		if err == nil {
			return state
		}
	}
	return nil
}

func (s *Server) withCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type")
		if r.Method == http.MethodOptions {
			w.WriteHeader(http.StatusNoContent)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, data any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(data)
}

func tailFile(path string, n int) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var lines []string
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}

	if len(lines) > n {
		lines = lines[len(lines)-n:]
	}
	return lines, nil
}
