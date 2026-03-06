package config

import (
	"os"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// Resources holds computed system resource values for provider thread/rate tuning.
type Resources struct {
	Cores        int
	RamGB        int
	ThreadsFull  int           // cores * 1 — CPU-bound
	ThreadsHeavy int           // cores * 2 — IO-bound
	ThreadsLight int           // cores * 4 — lightweight probes
	ThreadsCrawl int           // cores * 3 — crawling
	ThreadsCDP   int           // min(5, cores*2) — concurrent CDP tabs
	ThreadsDNS   int           // cores * 10 — DNS lookups
	RateFull     int           // 5000 req/s
	RateHeavy    int           // 1000 req/s
	RateNuclei   int           // 500 req/s
	RateCrawl    int           // 200 req/s
	TimeoutHTTP  time.Duration // 10s
	TimeoutDNS   time.Duration // 5s
	TimeoutScan  time.Duration // 30s
}

// DetectResources auto-detects CPU/RAM, respects cgroup limits and env overrides.
func DetectResources(cfg *ResourcesConfig) *Resources {
	cores := runtime.NumCPU()
	ramGB := getSystemRAM()

	// Docker cgroup v2 limits
	if cg := readCgroupCPU(); cg > 0 {
		cores = cg
	}
	if cg := readCgroupMem(); cg > 0 {
		ramGB = int(cg / (1024 * 1024 * 1024))
	}

	// Env override
	if v := os.Getenv("RECON0_THREADS"); v != "" && v != "0" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cores = n
		}
	}

	// Config max_threads cap
	if cfg != nil && cfg.MaxThreads > 0 && cores > cfg.MaxThreads {
		cores = cfg.MaxThreads
	}

	maxRate := 5000
	if cfg != nil && cfg.MaxRate > 0 {
		maxRate = cfg.MaxRate
	}
	if v := os.Getenv("RECON0_MAX_RATE"); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			maxRate = n
		}
	}

	return &Resources{
		Cores:        cores,
		RamGB:        ramGB,
		ThreadsFull:  cores,
		ThreadsHeavy: cores * 2,
		ThreadsLight: cores * 4,
		ThreadsCrawl: cores * 3,
		ThreadsCDP:   min(5, cores*2),
		ThreadsDNS:   cores * 10,
		RateFull:     maxRate,
		RateHeavy:    min(1000, maxRate),
		RateNuclei:   min(500, maxRate),
		RateCrawl:    min(200, maxRate),
		TimeoutHTTP:  10 * time.Second,
		TimeoutDNS:   5 * time.Second,
		TimeoutScan:  30 * time.Second,
	}
}

func getSystemRAM() int {
	// Try /proc/meminfo (Linux)
	data, err := os.ReadFile("/proc/meminfo")
	if err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "MemTotal:") {
				fields := strings.Fields(line)
				if len(fields) >= 2 {
					kb, _ := strconv.ParseInt(fields[1], 10, 64)
					return int(kb / 1024 / 1024)
				}
			}
		}
	}

	// macOS fallback: use Go's runtime estimate
	// On macOS /proc doesn't exist, approximate from runtime
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return max(int(m.Sys/(1024*1024*1024)), 4) // minimum 4GB assumption
}

func readCgroupCPU() int {
	// cgroup v2: /sys/fs/cgroup/cpu.max
	data, err := os.ReadFile("/sys/fs/cgroup/cpu.max")
	if err != nil {
		return 0
	}
	parts := strings.Fields(string(data))
	if len(parts) < 2 || parts[0] == "max" {
		return 0
	}
	quota, _ := strconv.ParseInt(parts[0], 10, 64)
	period, _ := strconv.ParseInt(parts[1], 10, 64)
	if period == 0 {
		return 0
	}
	return int(quota / period)
}

func readCgroupMem() int64 {
	// cgroup v2: /sys/fs/cgroup/memory.max
	data, err := os.ReadFile("/sys/fs/cgroup/memory.max")
	if err != nil {
		return 0
	}
	s := strings.TrimSpace(string(data))
	if s == "max" {
		return 0
	}
	v, _ := strconv.ParseInt(s, 10, 64)
	return v
}
