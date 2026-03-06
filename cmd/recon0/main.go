package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"runtime"
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

	// Background update check (non-blocking, only for interactive commands)
	var updateMsg chan string
	cmd := os.Args[1]
	switch cmd {
	case "run", "serve", "scan", "status", "list", "providers", "version":
		updateMsg = checkUpdateBackground()
	}

	switch cmd {
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
	case "update":
		cmdUpdate()
	case "uninstall":
		cmdUninstall()
	case "version":
		fmt.Printf("recon0 %s\n", version)
	case "help", "-h", "--help":
		printUsage()
	default:
		fmt.Fprintf(os.Stderr, "Unknown command: %s\n", os.Args[1])
		printUsage()
		os.Exit(1)
	}

	// Show update notice if available (non-blocking: skip if check hasn't finished)
	if updateMsg != nil {
		select {
		case msg := <-updateMsg:
			if msg != "" {
				fmt.Fprintln(os.Stderr, msg)
			}
		default:
		}
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
	fmt.Println("  recon0 update [--check]                                  Self-update to latest release")
	fmt.Println("  recon0 uninstall [--purge]                               Remove recon0 binary and data")
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

// ── update: self-update from GitHub Releases ──

const updateRepo = "badchars/recon0"

func cmdUpdate() {
	checkOnly := false
	for i := 2; i < len(os.Args); i++ {
		if os.Args[i] == "--check" || os.Args[i] == "-n" {
			checkOnly = true
		}
	}

	// Container detection
	if isContainer() {
		fmt.Println("Warning: running inside a container — self-update is not recommended.")
		fmt.Println("Rebuild the Docker image instead: docker build -t recon0 .")
		if !checkOnly {
			os.Exit(1)
		}
	}

	fmt.Printf("Current version: %s\n", version)
	fmt.Printf("Checking for updates...\n")

	// Fetch latest release from GitHub API
	release, err := fetchLatestRelease()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to check for updates: %v\n", err)
		os.Exit(1)
	}

	latest := strings.TrimPrefix(release.TagName, "v")
	current := strings.TrimPrefix(version, "v")

	if current == latest || version == release.TagName {
		fmt.Printf("Already up to date (%s)\n", release.TagName)
		return
	}

	fmt.Printf("New version available: %s → %s\n", version, release.TagName)

	if checkOnly {
		fmt.Printf("Run 'recon0 update' to install.\n")
		return
	}

	// Find the correct asset for this OS/ARCH
	assetName := fmt.Sprintf("recon0-%s-%s.tar.gz", runtime.GOOS, runtime.GOARCH)
	var assetURL string
	for _, a := range release.Assets {
		if a.Name == assetName {
			assetURL = a.BrowserDownloadURL
			break
		}
	}
	if assetURL == "" {
		fmt.Fprintf(os.Stderr, "No release asset found for %s/%s (%s)\n", runtime.GOOS, runtime.GOARCH, assetName)
		fmt.Fprintf(os.Stderr, "Available assets:\n")
		for _, a := range release.Assets {
			fmt.Fprintf(os.Stderr, "  - %s\n", a.Name)
		}
		os.Exit(1)
	}

	// Find checksums file
	var checksumURL string
	for _, a := range release.Assets {
		if a.Name == "checksums.txt" {
			checksumURL = a.BrowserDownloadURL
			break
		}
	}

	// Download the asset
	fmt.Printf("Downloading %s...\n", assetName)
	tarData, err := downloadURL(assetURL)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Download failed: %v\n", err)
		os.Exit(1)
	}

	// Verify checksum
	if checksumURL != "" {
		fmt.Printf("Verifying checksum...\n")
		checksumData, err := downloadURL(checksumURL)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: could not download checksums: %v\n", err)
		} else {
			actualHash := sha256sum(tarData)
			expectedHash := findChecksum(string(checksumData), assetName)
			if expectedHash == "" {
				fmt.Fprintf(os.Stderr, "Warning: asset not found in checksums.txt\n")
			} else if actualHash != expectedHash {
				fmt.Fprintf(os.Stderr, "Checksum mismatch!\n")
				fmt.Fprintf(os.Stderr, "  expected: %s\n", expectedHash)
				fmt.Fprintf(os.Stderr, "  got:      %s\n", actualHash)
				os.Exit(1)
			} else {
				fmt.Printf("Checksum OK (%s)\n", actualHash[:16]+"...")
			}
		}
	}

	// Extract binary from tarball
	binary, err := extractFromTarGz(tarData, "recon0")
	if err != nil {
		fmt.Fprintf(os.Stderr, "Extract failed: %v\n", err)
		os.Exit(1)
	}

	// Replace current executable (atomic: write temp → rename)
	execPath, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot determine executable path: %v\n", err)
		os.Exit(1)
	}
	execPath, _ = filepath.EvalSymlinks(execPath)

	tmpPath := execPath + ".update"
	if err := os.WriteFile(tmpPath, binary, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "Cannot write update: %v\n", err)
		os.Exit(1)
	}

	if err := os.Rename(tmpPath, execPath); err != nil {
		os.Remove(tmpPath)
		fmt.Fprintf(os.Stderr, "Cannot replace binary: %v\n", err)
		fmt.Fprintf(os.Stderr, "Try: sudo recon0 update\n")
		os.Exit(1)
	}

	fmt.Printf("Updated to %s\n", release.TagName)
}

// ── uninstall ──

func cmdUninstall() {
	purge := false
	for i := 2; i < len(os.Args); i++ {
		if os.Args[i] == "--purge" {
			purge = true
		}
	}

	execPath, err := os.Executable()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Cannot determine executable path: %v\n", err)
		os.Exit(1)
	}
	execPath, _ = filepath.EvalSymlinks(execPath)

	fmt.Println("recon0 uninstall")
	fmt.Println()
	fmt.Printf("  Binary:  %s\n", execPath)

	// Detect data directories relative to binary or config
	cfg, _ := config.Load("")
	runsDir := ""
	if cfg != nil {
		abs, err := filepath.Abs(cfg.OutputDir)
		if err == nil {
			runsDir = abs
		}
	}

	if purge && runsDir != "" {
		fmt.Printf("  Data:    %s\n", runsDir)
	}

	fmt.Println()

	if !purge {
		fmt.Println("This will remove the recon0 binary.")
		fmt.Println("Scan data in runs/ will NOT be deleted.")
		fmt.Println("Use --purge to also remove all scan data.")
	} else {
		fmt.Println("This will remove the recon0 binary AND all scan data.")
	}

	fmt.Println()
	fmt.Print("Continue? [y/N] ")

	var answer string
	fmt.Scanln(&answer)
	answer = strings.ToLower(strings.TrimSpace(answer))
	if answer != "y" && answer != "yes" {
		fmt.Println("Cancelled.")
		return
	}

	// Remove scan data if --purge
	if purge && runsDir != "" {
		if _, err := os.Stat(runsDir); err == nil {
			fmt.Printf("Removing %s...\n", runsDir)
			if err := os.RemoveAll(runsDir); err != nil {
				fmt.Fprintf(os.Stderr, "Warning: could not remove %s: %v\n", runsDir, err)
			}
		}
	}

	// Remove config file if --purge
	if purge {
		for _, name := range []string{"recon0.yaml", "config.yaml"} {
			if _, err := os.Stat(name); err == nil {
				fmt.Printf("Removing %s...\n", name)
				os.Remove(name)
			}
		}
	}

	// Remove binary (must be last — we're deleting ourselves)
	fmt.Printf("Removing %s...\n", execPath)
	if err := os.Remove(execPath); err != nil {
		fmt.Fprintf(os.Stderr, "Cannot remove binary: %v\n", err)
		fmt.Fprintf(os.Stderr, "Try: sudo recon0 uninstall\n")
		os.Exit(1)
	}

	fmt.Println("recon0 has been uninstalled.")
}

// ── update check ──

// checkUpdateBackground starts a goroutine that checks for updates.
// Returns a channel that will receive a message string (empty if up to date).
// The check has a 3-second timeout so it never delays the main command.
func checkUpdateBackground() chan string {
	ch := make(chan string, 1)
	go func() {
		if version == "dev" {
			ch <- ""
			return
		}

		client := &http.Client{Timeout: 3 * time.Second}
		url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", updateRepo)
		req, _ := http.NewRequest("GET", url, nil)
		req.Header.Set("Accept", "application/vnd.github+json")
		req.Header.Set("User-Agent", "recon0/"+version)

		resp, err := client.Do(req)
		if err != nil || resp.StatusCode != 200 {
			ch <- ""
			return
		}
		defer resp.Body.Close()

		var release ghRelease
		if json.NewDecoder(resp.Body).Decode(&release) != nil {
			ch <- ""
			return
		}

		latest := strings.TrimPrefix(release.TagName, "v")
		current := strings.TrimPrefix(version, "v")
		if current == latest || version == release.TagName {
			ch <- ""
			return
		}

		ch <- fmt.Sprintf("\n\033[33m[!] Update available: %s → %s — run 'recon0 update' to install\033[0m", version, release.TagName)
	}()
	return ch
}

// ── update helpers ──

type ghRelease struct {
	TagName string    `json:"tag_name"`
	Assets  []ghAsset `json:"assets"`
}

type ghAsset struct {
	Name               string `json:"name"`
	BrowserDownloadURL string `json:"browser_download_url"`
}

func fetchLatestRelease() (*ghRelease, error) {
	url := fmt.Sprintf("https://api.github.com/repos/%s/releases/latest", updateRepo)
	req, _ := http.NewRequest("GET", url, nil)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("User-Agent", "recon0/"+version)

	client := &http.Client{Timeout: 15 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == 404 {
		return nil, fmt.Errorf("no releases found for %s", updateRepo)
	}
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("GitHub API returned %d", resp.StatusCode)
	}

	var release ghRelease
	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		return nil, fmt.Errorf("parse response: %w", err)
	}
	return &release, nil
}

func downloadURL(url string) ([]byte, error) {
	client := &http.Client{Timeout: 5 * time.Minute}
	resp, err := client.Get(url)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}

	return io.ReadAll(io.LimitReader(resp.Body, 100*1024*1024)) // 100MB limit
}

func sha256sum(data []byte) string {
	h := sha256.Sum256(data)
	return hex.EncodeToString(h[:])
}

func findChecksum(checksums, filename string) string {
	for _, line := range strings.Split(checksums, "\n") {
		parts := strings.Fields(line)
		if len(parts) == 2 && parts[1] == filename {
			return parts[0]
		}
	}
	return ""
}

func extractFromTarGz(data []byte, targetName string) ([]byte, error) {
	gzr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("gzip: %w", err)
	}
	defer gzr.Close()

	tr := tar.NewReader(gzr)
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("tar: %w", err)
		}
		// Match the binary name (may be in a subdirectory)
		base := filepath.Base(hdr.Name)
		if base == targetName && hdr.Typeflag == tar.TypeReg {
			return io.ReadAll(tr)
		}
	}
	return nil, fmt.Errorf("binary '%s' not found in archive", targetName)
}

func isContainer() bool {
	// Check /.dockerenv
	if _, err := os.Stat("/.dockerenv"); err == nil {
		return true
	}
	// Check cgroup for docker/lxc/kubepods
	data, err := os.ReadFile("/proc/1/cgroup")
	if err == nil {
		s := string(data)
		if strings.Contains(s, "docker") || strings.Contains(s, "lxc") || strings.Contains(s, "kubepods") {
			return true
		}
	}
	return false
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
