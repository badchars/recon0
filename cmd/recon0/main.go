package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/badchars/recon0/internal/api"
	"github.com/badchars/recon0/internal/config"
	"github.com/badchars/recon0/internal/log"
	"github.com/badchars/recon0/internal/pipeline"
	"github.com/badchars/recon0/internal/provider"
	"github.com/badchars/recon0/internal/queue"

	// Register all providers
	_ "github.com/badchars/recon0/internal/provider"
)

var version = "dev"

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	switch os.Args[1] {
	case "run":
		cmdRun()
	case "serve":
		cmdServe()
	case "scan":
		cmdScan()
	case "status":
		cmdStatus()
	case "list":
		cmdList()
	case "providers":
		cmdProviders()
	case "version":
		fmt.Printf("recon0 %s\n", version)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}
}

func printUsage() {
	fmt.Println("recon0 — bug bounty recon pipeline")
	fmt.Println()
	fmt.Println("Usage:")
	fmt.Println("  recon0 run <domain> [--program NAME] [--config PATH] [--from-stage STAGE]")
	fmt.Println("  recon0 serve [--port 8484] [--config PATH]              Start API + job queue")
	fmt.Println("  recon0 scan <domain> [--program NAME] [--remote HOST]   Queue a scan via API")
	fmt.Println("  recon0 status [RUN_ID] [--remote HOST]                  Show scan status")
	fmt.Println("  recon0 list                                             List all runs")
	fmt.Println("  recon0 providers                                        List providers")
	fmt.Println("  recon0 version                                          Show version")
}

// ── run: direct execution (no queue) ──

func cmdRun() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "Usage: recon0 run <domain> [--program NAME] [--config PATH] [--from-stage STAGE]")
		os.Exit(1)
	}

	domain := os.Args[2]
	program := domain
	configPath := ""
	fromStage := ""

	for i := 3; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--program", "-p":
			if i+1 < len(os.Args) {
				program = os.Args[i+1]
				i++
			}
		case "--config", "-c":
			if i+1 < len(os.Args) {
				configPath = os.Args[i+1]
				i++
			}
		case "--from-stage", "-f":
			if i+1 < len(os.Args) {
				fromStage = os.Args[i+1]
				i++
			}
		}
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Config error: %v\n", err)
		os.Exit(1)
	}

	res := config.DetectResources(&cfg.Resources)

	// --from-stage: reuse the latest run directory for this program
	var logger *log.Logger
	var logDir, runDir string
	var state *pipeline.State

	if fromStage != "" {
		if existingDir, found := pipeline.FindLatestRunDir(cfg.OutputDir, program); found {
			runDir = existingDir
			logDir = filepath.Join(runDir, "logs")
			os.MkdirAll(logDir, 0755)

			logLevel := log.INFO
			switch strings.ToLower(cfg.Log.Level) {
			case "debug":
				logLevel = log.DEBUG
			case "warn":
				logLevel = log.WARN
			case "error":
				logLevel = log.ERROR
			}
			logFile := ""
			if cfg.Log.File {
				logFile = filepath.Join(logDir, "pipeline.log")
			}
			logger = log.New(logLevel, cfg.Log.Format, logFile)

			stateFile := filepath.Join(runDir, "state.json")
			var err error
			state, err = pipeline.LoadState(stateFile)
			if err != nil {
				fmt.Fprintf(os.Stderr, "Cannot load state from %s: %v\n", existingDir, err)
				os.Exit(1)
			}
			state.Status = "running"
		} else {
			fmt.Fprintf(os.Stderr, "No existing run found for program '%s'. Run without --from-stage first.\n", program)
			os.Exit(1)
		}
	} else {
		logger, logDir, runDir, state = setupRun(cfg, program, domain)
	}
	defer logger.Close()
	_ = logDir

	// Start API server if enabled
	if cfg.API.Enabled {
		srv := api.New(nil, cfg.OutputDir, logger)
		srv.SetState(state)
		go srv.Start(cfg.API.Listen, cfg.API.Port)
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		logger.Warn("Received shutdown signal, finishing current stage...")
		cancel()
	}()

	p := pipeline.New(cfg, res, logger, state, runDir)
	p.FromStage = fromStage
	if err := p.Run(ctx, domain, program); err != nil {
		logger.Errorf("Pipeline error: %v", err)
		os.Exit(1)
	}

	fmt.Println()
	fmt.Println("=========================================")
	fmt.Print(state.Query())
	fmt.Println("=========================================")
}

// ── serve: API server + job queue worker ──

func cmdServe() {
	configPath := ""
	port := 0

	for i := 2; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--config", "-c":
			if i+1 < len(os.Args) {
				configPath = os.Args[i+1]
				i++
			}
		case "--port":
			if i+1 < len(os.Args) {
				fmt.Sscanf(os.Args[i+1], "%d", &port)
				i++
			}
		}
	}

	cfg, err := config.Load(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Config error: %v\n", err)
		os.Exit(1)
	}

	if port > 0 {
		cfg.API.Port = port
	}

	// Logger for daemon mode
	logLevel := log.INFO
	switch strings.ToLower(cfg.Log.Level) {
	case "debug":
		logLevel = log.DEBUG
	case "warn":
		logLevel = log.WARN
	case "error":
		logLevel = log.ERROR
	}
	logger := log.New(logLevel, cfg.Log.Format, "")
	defer logger.Close()

	os.MkdirAll(cfg.OutputDir, 0755)

	// Job queue with disk persistence
	queueFile := filepath.Join(cfg.OutputDir, "queue.json")
	q := queue.New(queueFile)

	// API server
	srv := api.New(q, cfg.OutputDir, logger)

	// Graceful shutdown
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	sigCh := make(chan os.Signal, 1)
	signal.Notify(sigCh, syscall.SIGINT, syscall.SIGTERM)
	go func() {
		<-sigCh
		logger.Warn("Shutdown signal received, finishing current scan...")
		cancel()
	}()

	// Start API server
	go func() {
		if err := srv.Start(cfg.API.Listen, cfg.API.Port); err != nil {
			logger.Errorf("API server error: %v", err)
		}
	}()

	logger.Info("recon0 daemon started — waiting for jobs")
	logger.Infof("Queue file: %s", queueFile)

	// Worker loop
	for {
		if ctx.Err() != nil {
			break
		}

		job := q.Next()
		if job == nil {
			// No jobs, wait and check again
			select {
			case <-ctx.Done():
				break
			case <-time.After(2 * time.Second):
				continue
			}
			continue
		}

		// Run the job
		res := config.DetectResources(&cfg.Resources)
		runDir, _ := pipeline.ResolveRunDir(cfg.OutputDir, job.Program, cfg.Resume)
		os.MkdirAll(runDir, 0755)
		logDir := filepath.Join(runDir, "logs")
		os.MkdirAll(logDir, 0755)

		jobID := filepath.Base(runDir)
		q.MarkRunning(job.ID, jobID)

		stateFile := filepath.Join(runDir, "state.json")
		state := pipeline.NewState(stateFile, jobID, job.Program, job.Domain)
		srv.SetState(state)

		// Job-specific log file
		logFile := ""
		if cfg.Log.File {
			logFile = filepath.Join(logDir, "pipeline.log")
		}
		jobLogger := log.New(logLevel, cfg.Log.Format, logFile)

		jobLogger.Infof("Starting scan: %s (%s) — queue job %s", jobID, job.Domain, job.ID)

		p := pipeline.New(cfg, res, jobLogger, state, runDir)
		if err := p.Run(ctx, job.Domain, job.Program); err != nil {
			jobLogger.Errorf("Pipeline error: %v", err)
			q.MarkFailed(job.ID, err.Error())
		} else {
			q.MarkDone(job.ID)
		}

		jobLogger.Close()
		srv.SetState(nil)

		logger.Infof("Scan complete: %s — %s", jobID, state.Status)
	}

	logger.Info("recon0 daemon stopped")
}

// ── scan: submit a scan to the queue via API ──

func cmdScan() {
	if len(os.Args) < 3 {
		fmt.Fprintln(os.Stderr, "Usage: recon0 scan <domain> [--program NAME] [--remote HOST:PORT]")
		os.Exit(1)
	}

	domain := os.Args[2]
	program := domain
	remote := "localhost:8484"

	for i := 3; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--program", "-p":
			if i+1 < len(os.Args) {
				program = os.Args[i+1]
				i++
			}
		case "--remote", "-r":
			if i+1 < len(os.Args) {
				remote = os.Args[i+1]
				i++
			}
		}
	}

	body, _ := json.Marshal(map[string]string{
		"domain":  domain,
		"program": program,
	})

	url := fmt.Sprintf("http://%s/api/scan", remote)
	resp, err := http.Post(url, "application/json", bytes.NewReader(body))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot connect to %s: %v\n", remote, err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	var result map[string]any
	json.NewDecoder(resp.Body).Decode(&result)

	fmt.Printf("Scan queued:\n")
	fmt.Printf("  Queue ID:  %v\n", result["queue_id"])
	fmt.Printf("  Domain:    %v\n", result["domain"])
	fmt.Printf("  Program:   %v\n", result["program"])
	fmt.Printf("  Position:  %v\n", result["position"])
}

// ── status ──

func cmdStatus() {
	cfg, _ := config.Load("")
	runID := ""
	remote := ""

	for i := 2; i < len(os.Args); i++ {
		switch os.Args[i] {
		case "--remote", "-r":
			if i+1 < len(os.Args) {
				remote = os.Args[i+1]
				i++
			}
		default:
			if runID == "" {
				runID = os.Args[i]
			}
		}
	}

	// Remote status
	if remote != "" {
		url := fmt.Sprintf("http://%s/api/status", remote)
		if runID != "" {
			url = fmt.Sprintf("http://%s/api/status/%s", remote, runID)
		}
		resp, err := http.Get(url)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot connect to %s: %v\n", remote, err)
			os.Exit(1)
		}
		defer resp.Body.Close()
		data, _ := io.ReadAll(resp.Body)

		// Try to parse as state and print Query()
		var state pipeline.State
		if json.Unmarshal(data, &state) == nil && state.JobID != "" {
			fmt.Print(state.Query())
		} else {
			fmt.Println(string(data))
		}
		return
	}

	// Local status
	if runID != "" {
		stateFile := filepath.Join(cfg.OutputDir, runID, "state.json")
		state, err := pipeline.LoadState(stateFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Cannot read state: %v\n", err)
			os.Exit(1)
		}
		fmt.Print(state.Query())
		return
	}

	// Find most recent run
	entries, err := os.ReadDir(cfg.OutputDir)
	if err != nil || len(entries) == 0 {
		fmt.Println("No runs found.")
		return
	}
	latest := entries[len(entries)-1].Name()
	stateFile := filepath.Join(cfg.OutputDir, latest, "state.json")
	state, err := pipeline.LoadState(stateFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot read state: %v\n", err)
		os.Exit(1)
	}
	fmt.Print(state.Query())
}

// ── list ──

func cmdList() {
	cfg, _ := config.Load("")

	entries, err := os.ReadDir(cfg.OutputDir)
	if err != nil || len(entries) == 0 {
		fmt.Println("No runs found.")
		return
	}

	fmt.Printf("  %-35s %-10s %-15s %s\n", "ID", "Status", "Domain", "Duration")
	fmt.Printf("  %-35s %-10s %-15s %s\n", strings.Repeat("─", 35), strings.Repeat("─", 10), strings.Repeat("─", 15), strings.Repeat("─", 10))

	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		stateFile := filepath.Join(cfg.OutputDir, e.Name(), "state.json")
		state, err := pipeline.LoadState(stateFile)
		if err != nil {
			continue
		}
		dur := ""
		if state.FinishedAt != nil {
			dur = *state.FinishedAt
		}
		fmt.Printf("  %-35s %-10s %-15s %s\n", state.JobID, state.Status, state.Domain, dur)
	}
}

// ── providers ──

func cmdProviders() {
	cfg, _ := config.Load("")

	fmt.Printf("  %-14s %-12s %-10s %-20s\n", "Provider", "Stage", "Status", "Binary")
	fmt.Printf("  %-14s %-12s %-10s %-20s\n", strings.Repeat("─", 14), strings.Repeat("─", 12), strings.Repeat("─", 10), strings.Repeat("─", 20))

	for _, p := range provider.All() {
		status := "enabled"
		if !cfg.ProviderEnabled(p.Name()) {
			status = "disabled"
		}

		binary := "(built-in)"
		if err := p.Check(); err != nil {
			binary = "NOT FOUND"
		} else {
			if path, err := lookPath(p.Name()); err == nil {
				binary = path
			}
		}

		fmt.Printf("  %-14s %-12s %-10s %-20s\n", p.Name(), p.Stage(), status, binary)
	}
}

// ── helpers ──

func setupRun(cfg *config.Config, program, domain string) (*log.Logger, string, string, *pipeline.State) {
	os.MkdirAll(cfg.OutputDir, 0755)
	runDir, isResume := pipeline.ResolveRunDir(cfg.OutputDir, program, cfg.Resume)
	os.MkdirAll(runDir, 0755)
	logDir := filepath.Join(runDir, "logs")
	os.MkdirAll(logDir, 0755)

	logLevel := log.INFO
	switch strings.ToLower(cfg.Log.Level) {
	case "debug":
		logLevel = log.DEBUG
	case "warn":
		logLevel = log.WARN
	case "error":
		logLevel = log.ERROR
	}

	logFile := ""
	if cfg.Log.File {
		logFile = filepath.Join(logDir, "pipeline.log")
	}
	logger := log.New(logLevel, cfg.Log.Format, logFile)

	stateFile := filepath.Join(runDir, "state.json")
	var state *pipeline.State
	jobID := filepath.Base(runDir)

	if isResume {
		var err error
		state, err = pipeline.LoadState(stateFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Failed to load state for resume: %v\n", err)
			os.Exit(1)
		}
		state.Status = "running"
		logger.Info("Resuming pipeline: " + jobID)
	} else {
		state = pipeline.NewState(stateFile, jobID, program, domain)
	}

	return logger, logDir, runDir, state
}

func lookPath(name string) (string, error) {
	path := os.Getenv("PATH")
	for _, dir := range strings.Split(path, ":") {
		full := filepath.Join(dir, name)
		if _, err := os.Stat(full); err == nil {
			return full, nil
		}
	}
	return "", fmt.Errorf("not found")
}
