// Package programs stores bug bounty program metadata (name, vendor,
// link, scope) backed by a single JSON file.
//
// Programs are addressed by slug-style name. Name is immutable: once
// created, it can't be renamed (to avoid orphaning vulnerabilities and
// run dirs that reference it by name).
package programs

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"sync"
	"time"
)

var slugRe = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{0,62}$`)

// Program is a single bug bounty program record.
type Program struct {
	Name        string   `json:"name"`
	Description string   `json:"description"`
	Vendor      string   `json:"vendor"`
	VendorLink  string   `json:"vendor_link"`
	Scope       []string `json:"scope"`
	CreatedAt   string   `json:"created_at"`
	UpdatedAt   string   `json:"updated_at"`
	Version     int      `json:"version"`
}

// Store is the on-disk programs collection with a mutex.
type Store struct {
	mu    sync.Mutex
	file  string
	items map[string]*Program // keyed by name
}

var (
	ErrVersionConflict = errors.New("version conflict")
	ErrAlreadyExists   = errors.New("program already exists")
	ErrNotFound        = errors.New("program not found")
	ErrInvalidName     = errors.New("invalid name (must be slug: a-z0-9-)")
)

// New loads or starts a programs store.
func New(file string) (*Store, error) {
	s := &Store{file: file, items: map[string]*Program{}}
	if err := s.load(); err != nil {
		return nil, err
	}
	return s, nil
}

// List returns all programs sorted by name.
func (s *Store) List() []*Program {
	s.mu.Lock()
	defer s.mu.Unlock()

	out := make([]*Program, 0, len(s.items))
	for _, p := range s.items {
		cp := *p
		out = append(out, &cp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

// Get returns a program by name, or (nil, false) if absent.
func (s *Store) Get(name string) (*Program, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	p, ok := s.items[name]
	if !ok {
		return nil, false
	}
	cp := *p
	return &cp, true
}

// Create inserts a new program. Returns ErrAlreadyExists if the name is taken.
func (s *Store) Create(p *Program) (*Program, error) {
	if !slugRe.MatchString(p.Name) {
		return nil, ErrInvalidName
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.items[p.Name]; exists {
		return nil, ErrAlreadyExists
	}
	now := nowUTC()
	stored := &Program{
		Name:        p.Name,
		Description: p.Description,
		Vendor:      p.Vendor,
		VendorLink:  p.VendorLink,
		Scope:       cleanScope(p.Scope),
		CreatedAt:   now,
		UpdatedAt:   now,
		Version:     1,
	}
	s.items[p.Name] = stored
	if err := s.save(); err != nil {
		return nil, err
	}
	cp := *stored
	return &cp, nil
}

// Update modifies an existing program. Name is ignored from the update
// payload — the URL-supplied name is authoritative. expected_version must
// match the stored version; otherwise ErrVersionConflict.
func (s *Store) Update(name string, fields *Program, expectedVersion int) (*Program, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	cur, ok := s.items[name]
	if !ok {
		return nil, ErrNotFound
	}
	if expectedVersion != cur.Version {
		return nil, ErrVersionConflict
	}
	cur.Description = fields.Description
	cur.Vendor = fields.Vendor
	cur.VendorLink = fields.VendorLink
	cur.Scope = cleanScope(fields.Scope)
	cur.UpdatedAt = nowUTC()
	cur.Version++
	if err := s.save(); err != nil {
		return nil, err
	}
	cp := *cur
	return &cp, nil
}

// Delete removes a program by name. Returns ErrNotFound if absent.
func (s *Store) Delete(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.items[name]; !ok {
		return ErrNotFound
	}
	delete(s.items, name)
	return s.save()
}

// ── persistence ──

type diskState struct {
	Programs []*Program `json:"programs"`
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
	for _, p := range ds.Programs {
		if p != nil && p.Name != "" {
			s.items[p.Name] = p
		}
	}
	return nil
}

// save atomically writes the store. Caller holds s.mu.
func (s *Store) save() error {
	if s.file == "" {
		return nil
	}
	progs := make([]*Program, 0, len(s.items))
	for _, p := range s.items {
		progs = append(progs, p)
	}
	sort.Slice(progs, func(i, j int) bool { return progs[i].Name < progs[j].Name })
	data, err := json.MarshalIndent(diskState{Programs: progs}, "", "  ")
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

// cleanScope trims, dedupes, and removes empty entries from a scope list.
func cleanScope(in []string) []string {
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
