package queue

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// Job represents a scan job in the queue.
//
// Domain is a denormalised display field — the first host across both
// buckets — kept for the panel UI which renders a single "domain" cell.
// Wildcards and FixedHosts hold the canonical scan input.
type Job struct {
	ID         string   `json:"id"`
	Domain     string   `json:"domain"`
	Program    string   `json:"program"`
	Wildcards  []string `json:"wildcards,omitempty"`
	FixedHosts []string `json:"fixed_hosts,omitempty"`
	Status     string   `json:"status"` // queued | running | done | failed | cancelled
	CreatedAt  string   `json:"created_at"`
	StartedAt  string   `json:"started_at,omitempty"`
	DoneAt     string   `json:"done_at,omitempty"`
	RunID      string   `json:"run_id,omitempty"`
	Error      string   `json:"error,omitempty"`
}

// Queue manages scan jobs with disk persistence.
type Queue struct {
	mu      sync.Mutex
	jobs    []*Job
	counter int
	file    string
}

// New creates a queue, loading any existing jobs from disk.
func New(file string) *Queue {
	q := &Queue{file: file}
	q.load()
	return q
}

// Add enqueues a single-domain scan, treating the domain as a wildcard
// (subfinder/amass will enumerate). Back-compat shim around AddBuckets.
func (q *Queue) Add(domain, program string) *Job {
	return q.AddBuckets([]string{domain}, nil, program)
}

// AddBuckets enqueues a scan with explicit wildcard / fixed-host buckets.
// Domain is set to the first host across the union for panel display.
func (q *Queue) AddBuckets(wildcards, fixedHosts []string, program string) *Job {
	q.mu.Lock()
	defer q.mu.Unlock()

	q.counter++
	display := ""
	if len(wildcards) > 0 {
		display = wildcards[0]
	} else if len(fixedHosts) > 0 {
		display = fixedHosts[0]
	}
	job := &Job{
		ID:         fmt.Sprintf("q-%03d", q.counter),
		Domain:     display,
		Program:    program,
		Wildcards:  wildcards,
		FixedHosts: fixedHosts,
		Status:     "queued",
		CreatedAt:  nowUTC(),
	}
	q.jobs = append(q.jobs, job)
	q.save()
	return job
}

// Next returns the next queued job, or nil if none available.
func (q *Queue) Next() *Job {
	q.mu.Lock()
	defer q.mu.Unlock()

	for _, j := range q.jobs {
		if j.Status == "queued" {
			return j
		}
	}
	return nil
}

// MarkRunning marks a job as running with the given run ID.
func (q *Queue) MarkRunning(id, runID string) {
	q.mu.Lock()
	defer q.mu.Unlock()

	for _, j := range q.jobs {
		if j.ID == id {
			j.Status = "running"
			j.StartedAt = nowUTC()
			j.RunID = runID
			break
		}
	}
	q.save()
}

// MarkDone marks a job as done.
func (q *Queue) MarkDone(id string) {
	q.mu.Lock()
	defer q.mu.Unlock()

	for _, j := range q.jobs {
		if j.ID == id {
			j.Status = "done"
			j.DoneAt = nowUTC()
			break
		}
	}
	q.save()
}

// MarkFailed marks a job as failed with an error message.
func (q *Queue) MarkFailed(id, errMsg string) {
	q.mu.Lock()
	defer q.mu.Unlock()

	for _, j := range q.jobs {
		if j.ID == id {
			j.Status = "failed"
			j.DoneAt = nowUTC()
			j.Error = errMsg
			break
		}
	}
	q.save()
}

// Remove removes a job from the queue (only if queued).
func (q *Queue) Remove(id string) bool {
	q.mu.Lock()
	defer q.mu.Unlock()

	for i, j := range q.jobs {
		if j.ID == id && j.Status == "queued" {
			q.jobs = append(q.jobs[:i], q.jobs[i+1:]...)
			q.save()
			return true
		}
	}
	return false
}

// List returns all jobs.
func (q *Queue) List() []*Job {
	q.mu.Lock()
	defer q.mu.Unlock()

	result := make([]*Job, len(q.jobs))
	copy(result, q.jobs)
	return result
}

// Current returns the currently running job, or nil.
func (q *Queue) Current() *Job {
	q.mu.Lock()
	defer q.mu.Unlock()

	for _, j := range q.jobs {
		if j.Status == "running" {
			return j
		}
	}
	return nil
}

// Position returns the queue position of a job (1-based), or 0 if not queued.
func (q *Queue) Position(id string) int {
	q.mu.Lock()
	defer q.mu.Unlock()

	pos := 0
	for _, j := range q.jobs {
		if j.Status == "queued" {
			pos++
			if j.ID == id {
				return pos
			}
		}
	}
	return 0
}

// PendingCount returns the number of queued jobs.
func (q *Queue) PendingCount() int {
	q.mu.Lock()
	defer q.mu.Unlock()

	count := 0
	for _, j := range q.jobs {
		if j.Status == "queued" {
			count++
		}
	}
	return count
}

// ── persistence ──

type diskState struct {
	Counter int    `json:"counter"`
	Jobs    []*Job `json:"jobs"`
}

func (q *Queue) save() {
	if q.file == "" {
		return
	}
	data, err := json.MarshalIndent(diskState{Counter: q.counter, Jobs: q.jobs}, "", "  ")
	if err != nil {
		return
	}
	os.MkdirAll(filepath.Dir(q.file), 0755)
	tmp := q.file + ".tmp"
	if os.WriteFile(tmp, data, 0644) == nil {
		os.Rename(tmp, q.file)
	}
}

func (q *Queue) load() {
	if q.file == "" {
		return
	}
	data, err := os.ReadFile(q.file)
	if err != nil {
		return
	}
	var ds diskState
	if json.Unmarshal(data, &ds) == nil {
		q.jobs = ds.Jobs
		q.counter = ds.Counter
		for _, j := range q.jobs {
			// Reset any "running" jobs to "queued" (crash recovery).
			if j.Status == "running" {
				j.Status = "queued"
				j.StartedAt = ""
				j.RunID = ""
			}
			// v1 upgrade: old jobs only have Domain set. Treat the domain
			// as a wildcard so re-running them produces today's behaviour.
			if len(j.Wildcards) == 0 && len(j.FixedHosts) == 0 && j.Domain != "" {
				j.Wildcards = []string{j.Domain}
			}
		}
	}
}

func nowUTC() string {
	return time.Now().UTC().Format(time.RFC3339)
}
