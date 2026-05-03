// Package annotations stores per-host manual review notes (description +
// review_status) shared across runs. Backed by a single JSON file.
//
// Hostname is the primary key; values are normalised (lowercase, no
// scheme/port/path) so the same host always maps to the same annotation
// regardless of what URL form the caller sends.
package annotations

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"
)

// ReviewStatus values tracked per host. The default ("not_reviewed") is
// implicit: hosts not present in the store are treated as not reviewed by
// the panel, so we never persist that value.
const (
	StatusNotReviewed = "not_reviewed"
	StatusReviewing   = "reviewing"
	StatusReviewed    = "reviewed"
)

var validStatuses = map[string]bool{
	StatusNotReviewed: true,
	StatusReviewing:   true,
	StatusReviewed:    true,
}

// Annotation is a single per-host record.
type Annotation struct {
	Description  string `json:"description"`
	ReviewStatus string `json:"review_status"`
	CreatedAt    string `json:"created_at"`
	UpdatedAt    string `json:"updated_at"`
	Version      int    `json:"version"`
}

// Store is the on-disk hostname → annotation map with a mutex.
type Store struct {
	mu    sync.Mutex
	file  string
	items map[string]*Annotation
}

// ErrVersionConflict is returned by Upsert when the caller's expected
// version doesn't match the stored record (optimistic concurrency).
var ErrVersionConflict = errors.New("version conflict")

// New loads (or starts) a store backed by the given file.
func New(file string) (*Store, error) {
	s := &Store{file: file, items: map[string]*Annotation{}}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// List returns a copy of the full hostname → annotation map.
func (s *Store) List() map[string]*Annotation {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make(map[string]*Annotation, len(s.items))
	for k, v := range s.items {
		cp := *v
		out[k] = &cp
	}
	return out
}

// Get returns one annotation by hostname, or (nil, false) if absent.
// Hostname is normalised before lookup.
func (s *Store) Get(hostname string) (*Annotation, bool) {
	key := Normalize(hostname)
	if key == "" {
		return nil, false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.items[key]
	if !ok {
		return nil, false
	}
	cp := *a
	return &cp, true
}

// Upsert creates or updates an annotation. expectedVersion of 0 means
// "create new only" — if the record exists, returns ErrVersionConflict.
// For updates, expectedVersion must match the stored version.
func (s *Store) Upsert(hostname, description, reviewStatus string, expectedVersion int) (*Annotation, error) {
	key := Normalize(hostname)
	if key == "" {
		return nil, fmt.Errorf("hostname required")
	}
	if reviewStatus == "" {
		reviewStatus = StatusNotReviewed
	}
	if !validStatuses[reviewStatus] {
		return nil, fmt.Errorf("invalid review_status: %s", reviewStatus)
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	now := nowUTC()
	existing, ok := s.items[key]
	if ok {
		if expectedVersion != existing.Version {
			return nil, ErrVersionConflict
		}
		existing.Description = description
		existing.ReviewStatus = reviewStatus
		existing.UpdatedAt = now
		existing.Version++
	} else {
		if expectedVersion != 0 {
			return nil, ErrVersionConflict
		}
		existing = &Annotation{
			Description:  description,
			ReviewStatus: reviewStatus,
			CreatedAt:    now,
			UpdatedAt:    now,
			Version:      1,
		}
		s.items[key] = existing
	}
	if err := s.save(); err != nil {
		return nil, err
	}
	cp := *existing
	return &cp, nil
}

// Delete removes an annotation. Returns true if removed, false if absent.
func (s *Store) Delete(hostname string) (bool, error) {
	key := Normalize(hostname)
	if key == "" {
		return false, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.items[key]; !ok {
		return false, nil
	}
	delete(s.items, key)
	if err := s.save(); err != nil {
		return false, err
	}
	return true, nil
}

// ── persistence ──

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
	if err := json.Unmarshal(data, &s.items); err != nil {
		return fmt.Errorf("unmarshal: %w", err)
	}
	if s.items == nil {
		s.items = map[string]*Annotation{}
	}
	return nil
}

// save writes the store atomically (tmp + rename). Caller must hold s.mu.
// Errors propagate so handlers can return 500 honestly.
func (s *Store) save() error {
	if s.file == "" {
		return nil
	}
	data, err := json.MarshalIndent(s.items, "", "  ")
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

// ── hostname normalization ──

var hostCharRe = regexp.MustCompile(`^[a-z0-9.\-]+$`)

// Normalize converts any caller-supplied hostname/URL into the canonical
// form used as the store key: lowercase, no scheme, no port, no path.
// Returns "" if the input doesn't yield a sensible hostname.
func Normalize(input string) string {
	s := strings.TrimSpace(strings.ToLower(input))
	if s == "" {
		return ""
	}
	// Strip scheme if present (https://, http://, etc.)
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	// Drop path/query/fragment
	if i := strings.IndexAny(s, "/?#"); i >= 0 {
		s = s[:i]
	}
	// Strip port using URL parser fallback (handles bracketed IPv6 too)
	if u, err := url.Parse("//" + s); err == nil && u.Host != "" {
		s = u.Hostname()
	}
	s = strings.Trim(s, ". ")
	if !hostCharRe.MatchString(s) {
		return ""
	}
	return s
}

func nowUTC() string {
	return time.Now().UTC().Format(time.RFC3339)
}
