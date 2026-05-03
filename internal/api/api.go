package api

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/badchars/recon0/internal/annotations"
	"github.com/badchars/recon0/internal/log"
	"github.com/badchars/recon0/internal/pipeline"
	"github.com/badchars/recon0/internal/programs"
	"github.com/badchars/recon0/internal/queue"
	"github.com/badchars/recon0/internal/vulnerabilities"
)

// Server holds the HTTP API state.
type Server struct {
	queue       *queue.Queue
	state       *pipeline.State // current running scan state (nil if idle)
	outputDir   string
	logger      *log.Logger
	mux         *http.ServeMux
	annotations *annotations.Store
	programs    *programs.Store
	vulns       *vulnerabilities.Store
}

// New creates an API server.
func New(q *queue.Queue, outputDir string, logger *log.Logger) *Server {
	annStore, err := annotations.New(filepath.Join(outputDir, "host-annotations.json"))
	if err != nil {
		// A corrupt annotations file shouldn't kill the daemon — log and
		// continue with an empty in-memory store. Operator can inspect/fix
		// the file; meanwhile annotations endpoints will start fresh.
		logger.Warnf("annotations: load failed: %v", err)
		annStore, _ = annotations.New("")
	}
	progStore, err := programs.New(filepath.Join(outputDir, "programs.json"))
	if err != nil {
		logger.Warnf("programs: load failed: %v", err)
		progStore, _ = programs.New("")
	}
	vulnStore, err := vulnerabilities.New(
		filepath.Join(outputDir, "vulnerabilities.json"),
		filepath.Join(outputDir, "vuln-attachments"),
	)
	if err != nil {
		logger.Warnf("vulnerabilities: load failed: %v", err)
		vulnStore, _ = vulnerabilities.New("", filepath.Join(outputDir, "vuln-attachments"))
	}
	s := &Server{
		queue:       q,
		outputDir:   outputDir,
		logger:      logger,
		mux:         http.NewServeMux(),
		annotations: annStore,
		programs:    progStore,
		vulns:       vulnStore,
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
	s.mux.HandleFunc("/api/runs/", s.handleRunSubresource)
	s.mux.HandleFunc("/api/logs/", s.handleLogs)
	s.mux.HandleFunc("/api/scan", s.handleScan)
	s.mux.HandleFunc("/api/queue", s.handleQueue)
	s.mux.HandleFunc("/api/queue/", s.handleQueueDelete)
	s.mux.HandleFunc("/api/host-annotations", s.handleHostAnnotations)
	s.mux.HandleFunc("/api/host-annotations/", s.handleHostAnnotationByHost)
	s.mux.HandleFunc("/api/programs", s.handlePrograms)
	s.mux.HandleFunc("/api/programs/", s.handleProgramByName)
	s.mux.HandleFunc("/api/vulnerabilities", s.handleVulns)
	s.mux.HandleFunc("/api/vulnerabilities/", s.handleVulnByID)
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

// ── Host annotations (F4) ──

func (s *Server) handleHostAnnotations(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}
	writeJSON(w, http.StatusOK, s.annotations.List())
}

func (s *Server) handleHostAnnotationByHost(w http.ResponseWriter, r *http.Request) {
	host := strings.TrimPrefix(r.URL.Path, "/api/host-annotations/")
	if host == "" {
		http.Error(w, "hostname required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		ann, ok := s.annotations.Get(host)
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, ann)

	case http.MethodPut:
		var req struct {
			Description     string `json:"description"`
			ReviewStatus    string `json:"review_status"`
			ExpectedVersion int    `json:"expected_version"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		ann, err := s.annotations.Upsert(host, req.Description, req.ReviewStatus, req.ExpectedVersion)
		if err != nil {
			if errors.Is(err, annotations.ErrVersionConflict) {
				cur, _ := s.annotations.Get(host)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusConflict)
				json.NewEncoder(w).Encode(map[string]any{
					"error":   "version conflict",
					"current": cur,
				})
				return
			}
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, ann)

	case http.MethodDelete:
		removed, err := s.annotations.Delete(host)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		if !removed {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"removed": host})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ── Vulnerabilities (F2/F5/F8) ──

func (s *Server) handleVulns(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.vulns.List())

	case http.MethodPost:
		var v vulnerabilities.Vulnerability
		if err := json.NewDecoder(r.Body).Decode(&v); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		created, err := s.vulns.Create(&v)
		if err != nil {
			if errors.Is(err, vulnerabilities.ErrInvalidField) {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusCreated, created)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleVulnByID(w http.ResponseWriter, r *http.Request) {
	// Path can be /api/vulnerabilities/:id OR /api/vulnerabilities/:id/attachments[/:name]
	rest := strings.TrimPrefix(r.URL.Path, "/api/vulnerabilities/")
	parts := strings.SplitN(rest, "/", 3)
	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "id required", http.StatusBadRequest)
		return
	}
	id := parts[0]

	if len(parts) >= 2 && parts[1] == "attachments" {
		s.handleVulnAttachments(w, r, id, parts)
		return
	}

	switch r.Method {
	case http.MethodGet:
		v, ok := s.vulns.Get(id)
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, v)

	case http.MethodPut:
		var req struct {
			vulnerabilities.Vulnerability
			ExpectedVersion int `json:"expected_version"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		updated, err := s.vulns.Update(id, &req.Vulnerability, req.ExpectedVersion)
		if err != nil {
			switch {
			case errors.Is(err, vulnerabilities.ErrNotFound):
				http.Error(w, err.Error(), http.StatusNotFound)
			case errors.Is(err, vulnerabilities.ErrVersionConflict):
				cur, _ := s.vulns.Get(id)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusConflict)
				json.NewEncoder(w).Encode(map[string]any{
					"error":   "version conflict",
					"current": cur,
				})
			case errors.Is(err, vulnerabilities.ErrInvalidField):
				http.Error(w, err.Error(), http.StatusBadRequest)
			default:
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}
		writeJSON(w, http.StatusOK, updated)

	case http.MethodDelete:
		if err := s.vulns.Delete(id); err != nil {
			if errors.Is(err, vulnerabilities.ErrNotFound) {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"removed": id})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

const maxAttachmentBytes = 10 * 1024 * 1024

var allowedAttachmentMIME = map[string]bool{
	"image/png":  true,
	"image/jpeg": true,
	"image/webp": true,
	"image/gif":  true,
}

func (s *Server) handleVulnAttachments(w http.ResponseWriter, r *http.Request, vulnID string, parts []string) {
	// parts: [id, "attachments"] or [id, "attachments", filename]
	if len(parts) == 2 {
		// /attachments — only POST allowed
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseMultipartForm(maxAttachmentBytes); err != nil {
			http.Error(w, "invalid multipart", http.StatusBadRequest)
			return
		}
		_, fh, err := r.FormFile("file")
		if err != nil {
			http.Error(w, "missing file field", http.StatusBadRequest)
			return
		}
		if fh.Size > maxAttachmentBytes {
			http.Error(w, "file too large (max 10MB)", http.StatusRequestEntityTooLarge)
			return
		}
		mt := fh.Header.Get("Content-Type")
		if !allowedAttachmentMIME[mt] {
			http.Error(w, "unsupported MIME type: "+mt, http.StatusBadRequest)
			return
		}
		stored, err := s.vulns.SaveAttachment(vulnID, fh)
		if err != nil {
			switch {
			case errors.Is(err, vulnerabilities.ErrNotFound):
				http.Error(w, "vuln not found", http.StatusNotFound)
			case errors.Is(err, vulnerabilities.ErrInvalidVulnID),
				errors.Is(err, vulnerabilities.ErrInvalidFilename):
				http.Error(w, err.Error(), http.StatusBadRequest)
			default:
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}
		url := fmt.Sprintf(
			"/api/vulnerabilities/%s/attachments/%s",
			vulnID, stored,
		)
		writeJSON(w, http.StatusCreated, map[string]string{
			"filename": stored,
			"url":      url,
		})
		return
	}

	// /attachments/:name
	filename := parts[2]
	switch r.Method {
	case http.MethodGet:
		full, err := s.vulns.AttachmentPath(vulnID, filename)
		if err != nil {
			if errors.Is(err, os.ErrNotExist) {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		http.ServeFile(w, r, full)

	case http.MethodDelete:
		if err := s.vulns.DeleteAttachment(vulnID, filename); err != nil {
			if errors.Is(err, os.ErrNotExist) {
				http.Error(w, "not found", http.StatusNotFound)
				return
			}
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"removed": filename})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// ── Programs (F1) ──

func (s *Server) handlePrograms(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, s.programs.List())

	case http.MethodPost:
		var p programs.Program
		if err := json.NewDecoder(r.Body).Decode(&p); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		created, err := s.programs.Create(&p)
		if err != nil {
			switch {
			case errors.Is(err, programs.ErrInvalidName):
				http.Error(w, err.Error(), http.StatusBadRequest)
			case errors.Is(err, programs.ErrAlreadyExists):
				http.Error(w, err.Error(), http.StatusConflict)
			default:
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}
		writeJSON(w, http.StatusCreated, created)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

func (s *Server) handleProgramByName(w http.ResponseWriter, r *http.Request) {
	name := strings.TrimPrefix(r.URL.Path, "/api/programs/")
	if name == "" {
		http.Error(w, "name required", http.StatusBadRequest)
		return
	}

	switch r.Method {
	case http.MethodGet:
		p, ok := s.programs.Get(name)
		if !ok {
			http.Error(w, "not found", http.StatusNotFound)
			return
		}
		writeJSON(w, http.StatusOK, p)

	case http.MethodPut:
		var req struct {
			Description     string   `json:"description"`
			Vendor          string   `json:"vendor"`
			VendorLink      string   `json:"vendor_link"`
			Scope           []string `json:"scope"`
			ExpectedVersion int      `json:"expected_version"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		p, err := s.programs.Update(name, &programs.Program{
			Description: req.Description,
			Vendor:      req.Vendor,
			VendorLink:  req.VendorLink,
			Scope:       req.Scope,
		}, req.ExpectedVersion)
		if err != nil {
			switch {
			case errors.Is(err, programs.ErrNotFound):
				http.Error(w, err.Error(), http.StatusNotFound)
			case errors.Is(err, programs.ErrVersionConflict):
				cur, _ := s.programs.Get(name)
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusConflict)
				json.NewEncoder(w).Encode(map[string]any{
					"error":   "version conflict",
					"current": cur,
				})
			default:
				http.Error(w, err.Error(), http.StatusInternalServerError)
			}
			return
		}
		writeJSON(w, http.StatusOK, p)

	case http.MethodDelete:
		if err := s.programs.Delete(name); err != nil {
			if errors.Is(err, programs.ErrNotFound) {
				http.Error(w, err.Error(), http.StatusNotFound)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"removed": name})

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}

// handleRunSubresource dispatches GET /api/runs/<id>/<subname> to the
// appropriate scan output file. Each known subresource maps to one file
// inside the run's work/ directory; unknown subresources return 404.
//
// File-not-found is treated as "stage didn't produce this output yet"
// and returns an empty array with 200, so the panel can render its
// table cleanly without special-casing missing data.
func (s *Server) handleRunSubresource(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/runs/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) < 2 || parts[0] == "" || parts[1] == "" {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	runID, sub := parts[0], parts[1]

	runDir := filepath.Join(s.outputDir, runID)
	if _, err := os.Stat(runDir); err != nil {
		http.Error(w, "run not found", http.StatusNotFound)
		return
	}

	type entry struct {
		path  string
		jsonl bool
	}
	work := filepath.Join(runDir, "work")
	subs := map[string]entry{
		"hosts":          {filepath.Join(work, "raw", "httpx.hosts.txt.json"), true},
		"findings":       {filepath.Join(work, "output", "findings.json"), true},
		"endpoints":      {filepath.Join(work, "output", "endpoints.json"), true},
		"smartfuzz":      {filepath.Join(work, "raw", "smartfuzz.findings.json"), true},
		"investigations": {filepath.Join(work, "output", "investigations.json"), false},
		"attack-surface": {filepath.Join(work, "output", "attack-surface.json"), false},
	}

	e, ok := subs[sub]
	if !ok {
		http.Error(w, "unknown subresource: "+sub, http.StatusNotFound)
		return
	}

	if _, err := os.Stat(e.path); os.IsNotExist(err) {
		// Stage hasn't run / produced output yet — render as empty.
		if e.jsonl {
			writeJSON(w, http.StatusOK, []any{})
		} else {
			writeJSON(w, http.StatusOK, nil)
		}
		return
	}

	var (
		data any
		err  error
	)
	if e.jsonl {
		data, err = readJSONL(e.path)
	} else {
		data, err = readJSON(e.path)
	}
	if err != nil {
		http.Error(w, "read failed: "+err.Error(), http.StatusInternalServerError)
		return
	}
	writeJSON(w, http.StatusOK, data)
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
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
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

// readJSONL parses a JSON-lines file into a slice. Empty/malformed lines
// are skipped (JSONL writers occasionally leave partial trailing lines
// during a crash; treating them as fatal would block the panel from
// rendering everything else).
func readJSONL(path string) ([]any, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	items := []any{}
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 16*1024*1024)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(bytes.TrimSpace(line)) == 0 {
			continue
		}
		var item any
		if err := json.Unmarshal(line, &item); err != nil {
			continue
		}
		items = append(items, item)
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return items, nil
}

// readJSON parses a single-document JSON file. Used for files that the
// pipeline writes as one well-formed JSON value (e.g. attack-surface.json,
// investigations.json — array as a whole, not per-line).
func readJSON(path string) (any, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var v any
	if err := json.Unmarshal(data, &v); err != nil {
		return nil, err
	}
	return v, nil
}
