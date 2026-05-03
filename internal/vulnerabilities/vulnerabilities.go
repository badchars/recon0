// Package vulnerabilities stores manually authored / promoted bug bounty
// vulnerability records. Backed by a single JSON file.
//
// Schema follows the F2/F5 spec from PANEL_FEATURES.md: a single markdown
// `description` field (PoC inlined as the user wishes), a `submission_status`
// reflecting bug bounty platform lifecycle, and a `bounty` amount.
package vulnerabilities

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

// Severity values mirror DSL findings: critical / high / medium / low / info.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
	SeverityInfo     = "info"
)

// SubmissionStatus values track the bug bounty platform lifecycle.
const (
	StatusWait      = "wait"
	StatusSubmitted = "submitted"
	StatusTriaged   = "triaged"
	StatusNA        = "na"
	StatusDuplicate = "duplicate"
)

var validSeverities = map[string]bool{
	SeverityCritical: true,
	SeverityHigh:     true,
	SeverityMedium:   true,
	SeverityLow:      true,
	SeverityInfo:     true,
}

var validStatuses = map[string]bool{
	StatusWait:      true,
	StatusSubmitted: true,
	StatusTriaged:   true,
	StatusNA:        true,
	StatusDuplicate: true,
}

// Vulnerability is a single record.
type Vulnerability struct {
	ID               string   `json:"id"`
	Title            string   `json:"title"`
	Severity         string   `json:"severity"`
	SubmissionStatus string   `json:"submission_status"`
	Bounty           float64  `json:"bounty"`
	Asset            string   `json:"asset"`
	Program          string   `json:"program,omitempty"`
	Description      string   `json:"description"`
	References       []string `json:"references"`
	Tags             []string `json:"tags"`
	SourceRunID      string   `json:"source_run_id,omitempty"`
	SourceFindingID  string   `json:"source_finding_id,omitempty"`
	CreatedAt        string   `json:"created_at"`
	UpdatedAt        string   `json:"updated_at"`
	Version          int      `json:"version"`
}

// Store is the on-disk vulnerabilities collection with a mutex.
type Store struct {
	mu             sync.Mutex
	file           string
	attachmentsDir string
	items          map[string]*Vulnerability // keyed by id
	dailyCounter   map[string]int            // YYYYMMDD → highest used NNN
}

var (
	ErrVersionConflict = errors.New("version conflict")
	ErrNotFound        = errors.New("vulnerability not found")
	ErrInvalidField    = errors.New("invalid field")
)

// New loads or starts a vulnerabilities store. attachmentsDir is the
// directory under which per-vuln attachment subdirs live.
func New(file, attachmentsDir string) (*Store, error) {
	s := &Store{
		file:           file,
		attachmentsDir: attachmentsDir,
		items:          map[string]*Vulnerability{},
		dailyCounter:   map[string]int{},
	}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// List returns all vulnerabilities sorted by created_at desc.
func (s *Store) List() []*Vulnerability {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]*Vulnerability, 0, len(s.items))
	for _, v := range s.items {
		cp := *v
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt > out[j].CreatedAt
	})
	return out
}

// Get returns a vulnerability by ID.
func (s *Store) Get(id string) (*Vulnerability, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	v, ok := s.items[id]
	if !ok {
		return nil, false
	}
	cp := *v
	return &cp, true
}

// Create inserts a new vulnerability with a server-generated ID.
func (s *Store) Create(in *Vulnerability) (*Vulnerability, error) {
	if err := validateInput(in, false); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	now := time.Now().UTC()
	id := s.nextID(now)
	stored := &Vulnerability{
		ID:               id,
		Title:            strings.TrimSpace(in.Title),
		Severity:         normalizeSeverity(in.Severity),
		SubmissionStatus: normalizeStatus(in.SubmissionStatus),
		Bounty:           in.Bounty,
		Asset:            strings.TrimSpace(in.Asset),
		Program:          strings.TrimSpace(in.Program),
		Description:      in.Description,
		References:       cleanList(in.References),
		Tags:             cleanList(in.Tags),
		SourceRunID:      strings.TrimSpace(in.SourceRunID),
		SourceFindingID:  strings.TrimSpace(in.SourceFindingID),
		CreatedAt:        now.Format(time.RFC3339),
		UpdatedAt:        now.Format(time.RFC3339),
		Version:          1,
	}
	s.items[id] = stored
	if err := s.save(); err != nil {
		return nil, err
	}
	cp := *stored
	return &cp, nil
}

// Update modifies an existing vulnerability. ID is immutable; expected_version
// must match the stored version.
func (s *Store) Update(id string, in *Vulnerability, expectedVersion int) (*Vulnerability, error) {
	if err := validateInput(in, true); err != nil {
		return nil, err
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	cur, ok := s.items[id]
	if !ok {
		return nil, ErrNotFound
	}
	if expectedVersion != cur.Version {
		return nil, ErrVersionConflict
	}
	cur.Title = strings.TrimSpace(in.Title)
	cur.Severity = normalizeSeverity(in.Severity)
	cur.SubmissionStatus = normalizeStatus(in.SubmissionStatus)
	cur.Bounty = in.Bounty
	cur.Asset = strings.TrimSpace(in.Asset)
	cur.Program = strings.TrimSpace(in.Program)
	cur.Description = in.Description
	cur.References = cleanList(in.References)
	cur.Tags = cleanList(in.Tags)
	cur.SourceRunID = strings.TrimSpace(in.SourceRunID)
	cur.SourceFindingID = strings.TrimSpace(in.SourceFindingID)
	cur.UpdatedAt = nowUTC()
	cur.Version++
	if err := s.save(); err != nil {
		return nil, err
	}
	cp := *cur
	return &cp, nil
}

// Delete removes a vulnerability and its attachments dir.
func (s *Store) Delete(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.items[id]; !ok {
		return ErrNotFound
	}
	delete(s.items, id)
	if err := s.save(); err != nil {
		return err
	}
	// Best-effort attachment cleanup — failure here is logged but not fatal.
	if s.attachmentsDir != "" {
		_ = os.RemoveAll(filepath.Join(s.attachmentsDir, id))
	}
	return nil
}

// nextID generates a v-YYYYMMDD-NNN id using a per-day counter. Caller
// holds s.mu.
func (s *Store) nextID(now time.Time) string {
	date := now.Format("20060102")
	s.dailyCounter[date]++
	return fmt.Sprintf("v-%s-%03d", date, s.dailyCounter[date])
}

// ── attachments (F8) ──

var safeFileNameRe = regexp.MustCompile(`^[a-zA-Z0-9._-]+$`)
var idRe = regexp.MustCompile(`^v-\d{8}-\d{3}$`)

// ErrInvalidVulnID is returned when an attachment endpoint receives a
// malformed vuln ID.
var ErrInvalidVulnID = errors.New("invalid vuln id")

// ErrInvalidFilename is returned when an attachment filename fails the
// safe-character whitelist.
var ErrInvalidFilename = errors.New("invalid filename")

// SaveAttachment writes a multipart upload to the per-vuln attachments dir.
// The stored filename is timestamp-prefixed to keep ordering and avoid
// collisions. The vuln must already exist.
func (s *Store) SaveAttachment(vulnID string, fh *multipart.FileHeader) (string, error) {
	if !idRe.MatchString(vulnID) {
		return "", ErrInvalidVulnID
	}
	s.mu.Lock()
	if _, ok := s.items[vulnID]; !ok {
		s.mu.Unlock()
		return "", ErrNotFound
	}
	s.mu.Unlock()

	cleanName := sanitizeFilename(fh.Filename)
	if cleanName == "" {
		return "", ErrInvalidFilename
	}
	ts := time.Now().UTC().Format("20060102T150405")
	storedName := ts + "-" + cleanName
	dir := filepath.Join(s.attachmentsDir, vulnID)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", fmt.Errorf("mkdir: %w", err)
	}

	src, err := fh.Open()
	if err != nil {
		return "", fmt.Errorf("open upload: %w", err)
	}
	defer src.Close()

	dst, err := os.Create(filepath.Join(dir, storedName))
	if err != nil {
		return "", fmt.Errorf("create file: %w", err)
	}
	defer dst.Close()

	if _, err := io.Copy(dst, src); err != nil {
		return "", fmt.Errorf("write file: %w", err)
	}
	return storedName, nil
}

// AttachmentPath returns the full disk path for a vuln attachment, or "" if
// not allowed (invalid id/name) or doesn't exist.
func (s *Store) AttachmentPath(vulnID, filename string) (string, error) {
	if !idRe.MatchString(vulnID) {
		return "", ErrInvalidVulnID
	}
	clean := sanitizeFilename(filename)
	if clean != filename {
		return "", ErrInvalidFilename
	}
	full := filepath.Join(s.attachmentsDir, vulnID, clean)
	if _, err := os.Stat(full); err != nil {
		if os.IsNotExist(err) {
			return "", os.ErrNotExist
		}
		return "", err
	}
	return full, nil
}

// DeleteAttachment removes a single attachment file.
func (s *Store) DeleteAttachment(vulnID, filename string) error {
	full, err := s.AttachmentPath(vulnID, filename)
	if err != nil {
		return err
	}
	return os.Remove(full)
}

// sanitizeFilename keeps only safe chars and rejects path-traversal tricks.
func sanitizeFilename(name string) string {
	name = filepath.Base(name)
	if name == "." || name == ".." || name == "" || strings.HasPrefix(name, ".") {
		return ""
	}
	if !safeFileNameRe.MatchString(name) {
		return ""
	}
	return name
}

// ── persistence ──

type diskState struct {
	Vulnerabilities []*Vulnerability `json:"vulnerabilities"`
	DailyCounter    map[string]int   `json:"daily_counter"`
}

func (s *Store) load() error {
	data, err := os.ReadFile(s.file)
	if err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("read: %w", err)
	}
	if len(data) == 0 {
		return nil
	}
	var ds diskState
	if err := json.Unmarshal(data, &ds); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}
	for _, v := range ds.Vulnerabilities {
		if v != nil && v.ID != "" {
			s.items[v.ID] = v
		}
	}
	if ds.DailyCounter != nil {
		s.dailyCounter = ds.DailyCounter
	}
	return nil
}

// save atomically writes the store. Caller holds s.mu.
func (s *Store) save() error {
	if s.file == "" {
		return nil
	}
	vulns := make([]*Vulnerability, 0, len(s.items))
	for _, v := range s.items {
		vulns = append(vulns, v)
	}
	sort.Slice(vulns, func(i, j int) bool { return vulns[i].ID < vulns[j].ID })
	data, err := json.MarshalIndent(diskState{
		Vulnerabilities: vulns,
		DailyCounter:    s.dailyCounter,
	}, "", "  ")
	if err != nil {
		return fmt.Errorf("marshal: %w", err)
	}
	if err := os.MkdirAll(filepath.Dir(s.file), 0755); err != nil {
		return fmt.Errorf("mkdir: %w", err)
	}
	tmp := s.file + ".tmp"
	if err := os.WriteFile(tmp, data, 0644); err != nil {
		return fmt.Errorf("write tmp: %w", err)
	}
	if err := os.Rename(tmp, s.file); err != nil {
		return fmt.Errorf("rename: %w", err)
	}
	return nil
}

// ── helpers ──

func validateInput(in *Vulnerability, isUpdate bool) error {
	_ = isUpdate
	if strings.TrimSpace(in.Title) == "" {
		return fmt.Errorf("%w: title required", ErrInvalidField)
	}
	if strings.TrimSpace(in.Asset) == "" {
		return fmt.Errorf("%w: asset required", ErrInvalidField)
	}
	if in.Severity != "" && !validSeverities[in.Severity] {
		return fmt.Errorf("%w: severity %q", ErrInvalidField, in.Severity)
	}
	if in.SubmissionStatus != "" && !validStatuses[in.SubmissionStatus] {
		return fmt.Errorf("%w: submission_status %q", ErrInvalidField, in.SubmissionStatus)
	}
	if in.Bounty < 0 {
		return fmt.Errorf("%w: bounty negative", ErrInvalidField)
	}
	return nil
}

func normalizeSeverity(s string) string {
	if s == "" || !validSeverities[s] {
		return SeverityMedium
	}
	return s
}

func normalizeStatus(s string) string {
	if s == "" || !validStatuses[s] {
		return StatusWait
	}
	return s
}

func cleanList(in []string) []string {
	seen := map[string]struct{}{}
	out := make([]string, 0, len(in))
	for _, s := range in {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		if _, dup := seen[s]; dup {
			continue
		}
		seen[s] = struct{}{}
		out = append(out, s)
	}
	return out
}

func nowUTC() string {
	return time.Now().UTC().Format(time.RFC3339)
}
