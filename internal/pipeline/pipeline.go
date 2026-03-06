package pipeline

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/badchars/recon0/internal/config"
	"github.com/badchars/recon0/internal/log"
	"github.com/badchars/recon0/internal/merge"
	"github.com/badchars/recon0/internal/provider"
)

// Pipeline is the main orchestrator.
type Pipeline struct {
	cfg             *config.Config
	res             *config.Resources
	logger          *log.Logger
	state           *State
	workDir         string
	logDir          string
	runDir          string
	completedStages int
	FromStage       string // if set, skip all stages before this one
}

// New creates a pipeline instance.
func New(cfg *config.Config, res *config.Resources, logger *log.Logger, state *State, runDir string) *Pipeline {
	return &Pipeline{
		cfg:     cfg,
		res:     res,
		logger:  logger,
		state:   state,
		workDir: filepath.Join(runDir, "work"),
		logDir:  filepath.Join(runDir, "logs"),
		runDir:  runDir,
	}
}

// Run executes the full pipeline for the given domain.
func (p *Pipeline) Run(ctx context.Context, domain, program string) error {
	// Create directory structure
	dirs := []string{
		p.workDir + "/input",
		p.workDir + "/raw",
		p.workDir + "/output",
		p.workDir + "/har",
		p.workDir + "/js",
		p.logDir,
	}
	for _, d := range dirs {
		os.MkdirAll(d, 0755)
	}

	// Write input domain file
	domainFile := filepath.Join(p.workDir, "input", "domains.txt")
	os.WriteFile(domainFile, []byte(domain+"\n"), 0644)

	// Record resources in state
	p.state.SetResources(p.res.Cores, p.res.RamGB, p.res.ThreadsFull, p.res.ThreadsHeavy, p.res.ThreadsLight)

	p.logger.Infof("Pipeline starting: %s (%s)", p.state.JobID, domain)
	p.logger.Infof("Resources: %d cores, %dGB RAM", p.res.Cores, p.res.RamGB)

	// --from-stage: reset state for stages from that point onwards
	if p.FromStage != "" {
		reached := false
		for _, s := range Stages {
			if s.Name == p.FromStage {
				reached = true
			}
			if reached {
				p.state.ResetStage(s.Name)
			}
		}
	}

	// Count already completed stages (for resume + progress)
	for _, s := range Stages {
		if p.state.StageDone(s.Name) {
			p.completedStages++
		}
	}

	// Execute stages
	reachedFromStage := p.FromStage == ""
	for _, stage := range Stages {
		if err := ctx.Err(); err != nil {
			p.logger.Warn("Pipeline cancelled")
			p.state.Finish("cancelled")
			return err
		}

		// --from-stage: skip stages before the requested start point
		if p.FromStage != "" && !reachedFromStage {
			if stage.Name == p.FromStage {
				reachedFromStage = true
			} else {
				p.logger.Infof("SKIP: stage '%s' (--from-stage %s)", stage.Name, p.FromStage)
				p.completedStages++
				continue
			}
		}

		// Resume: skip completed stages
		if p.state.StageDone(stage.Name) {
			p.logger.Infof("RESUME: skipping completed stage '%s'", stage.Name)
			continue
		}

		// Disk check
		if err := p.checkDisk(); err != nil {
			p.state.Finish("disk_full")
			return err
		}

		// Run stage
		if err := p.runStage(ctx, stage); err != nil {
			if stage.IsGate {
				p.logger.Errorf("Gate failed at '%s': %v", stage.Name, err)
				p.state.Finish("gate_failed")
				return err
			}
			p.logger.Warnf("Stage '%s' had errors: %v", stage.Name, err)
		}
	}

	p.state.Finish("done")
	p.logger.Info("Pipeline complete: " + p.state.JobID)
	p.logger.Info("Results: " + p.workDir + "/output/")

	return nil
}

func (p *Pipeline) runStage(ctx context.Context, stage Stage) error {
	p.logger.Stage(stage.Name)
	p.state.UpdateStage(stage.Name, "running", nil)

	input := StageInput(p.workDir, stage.Name)

	// Collect enabled providers for this stage
	var enabledProviders []provider.Provider
	for _, name := range stage.Providers {
		if !p.cfg.ProviderEnabled(name) {
			p.logger.Provider(name, "skipped (disabled in config)")
			p.state.UpdateProvider(stage.Name, name, "disabled", 0, 0, "")
			continue
		}
		prov, ok := provider.Get(name)
		if !ok {
			p.logger.Provider(name, "not registered, skipping")
			continue
		}
		enabledProviders = append(enabledProviders, prov)
	}

	if len(enabledProviders) == 0 {
		p.logger.Warnf("Stage '%s': no enabled providers", stage.Name)
		p.state.UpdateStage(stage.Name, "done", nil)
		return nil
	}

	// Run providers
	var results []*provider.Result
	progCtx := &provider.ProgressContext{
		StagesDone:  p.completedStages,
		StagesTotal: len(Stages),
	}

	if stage.Parallel && len(enabledProviders) > 1 {
		results = p.runParallel(ctx, stage.Name, enabledProviders, input, progCtx)
	} else {
		for _, prov := range enabledProviders {
			opts := p.buildOpts(prov, input)
			result := provider.RunProvider(ctx, prov, opts, p.state, p.logger, progCtx)
			results = append(results, result)
		}
	}

	// Post-stage: merge outputs
	stats := p.mergeStageOutputs(stage, results)

	// Gate check
	if stage.IsGate {
		outFile := StageOutput(p.workDir, stage.Name)
		count := merge.LineCount(outFile)
		if count == 0 {
			p.state.UpdateStage(stage.Name, "done", stats)
			return fmt.Errorf("no results from gate stage '%s'", stage.Name)
		}
	}

	p.state.UpdateStage(stage.Name, "done", stats)
	p.completedStages++

	// Metric: funnel conversion
	p.logFunnel(stage.Name, stats)

	return nil
}

func (p *Pipeline) runParallel(ctx context.Context, stageName string, provs []provider.Provider, input string, progCtx *provider.ProgressContext) []*provider.Result {
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		results []*provider.Result
	)

	for _, prov := range provs {
		wg.Add(1)
		go func(pr provider.Provider) {
			defer wg.Done()
			opts := p.buildOpts(pr, input)
			result := provider.RunProvider(ctx, pr, opts, p.state, p.logger, progCtx)
			mu.Lock()
			results = append(results, result)
			mu.Unlock()
		}(prov)
	}

	wg.Wait()
	return results
}

func (p *Pipeline) buildOpts(prov provider.Provider, input string) *provider.RunOpts {
	ext := ".txt"
	switch prov.OutputType() {
	case "endpoints", "findings", "intel":
		ext = ".json"
	}
	output := filepath.Join(p.workDir, "raw", prov.Name()+"."+prov.OutputType()+ext)

	return &provider.RunOpts{
		Input:   input,
		Output:  output,
		WorkDir: p.workDir,
		LogDir:  p.logDir,
		Config:  p.cfg.ProviderExtra(prov.Name()),
		Res:     p.res,
	}
}

func (p *Pipeline) mergeStageOutputs(stage Stage, results []*provider.Result) map[string]int {
	stageOut := StageOutput(p.workDir, stage.Name)
	stats := make(map[string]int)

	switch stage.Name {
	case "enum":
		files := merge.CollectByPattern(p.workDir+"/raw", "subdomains")
		count, _ := merge.TextDedup(files, stageOut)
		stats["subdomains"] = count
		p.logger.Infof("Merged subdomains: %d unique", count)

	case "resolve":
		// dnsx writes directly to output; copy to stage output
		src := filepath.Join(p.workDir, "raw", "dnsx.resolved.txt")
		copyFile(src, stageOut)
		count := merge.LineCount(stageOut)
		deadCount := merge.LineCount(filepath.Join(p.workDir, "raw", "dnsx.resolved-dead.txt"))
		stats["alive"] = count
		stats["dead"] = deadCount
		p.logger.Infof("DNS Gate: %d alive, %d dead", count, deadCount)

	case "probe":
		// httpx output is the live-hosts list (URLs with ports)
		src := filepath.Join(p.workDir, "raw", "httpx.hosts.txt")
		copyFile(src, stageOut)
		count := merge.LineCount(stageOut)
		uniqueHosts := merge.CountUniqueHosts(stageOut)
		stats["live_hosts"] = count
		stats["unique_hosts"] = uniqueHosts
		p.logger.Infof("Probe: %d URLs across %d unique hosts", count, uniqueHosts)

	case "crawl":
		src := filepath.Join(p.workDir, "raw", "cdpcrawl.urls.txt")
		copyFile(src, stageOut)
		count := merge.LineCount(stageOut)
		harCount := countFiles(filepath.Join(p.workDir, "har"), ".har")
		jsCount := countFiles(filepath.Join(p.workDir, "js"), "")
		stats["total_urls"] = count
		stats["har_files"] = harCount
		stats["js_files"] = jsCount
		p.logger.Infof("Crawl: %d URLs, %d HAR files, %d JS files", count, harCount, jsCount)

	case "portscan":
		src := filepath.Join(p.workDir, "raw", "naabu.ports.txt")
		copyFile(src, stageOut)
		count := merge.LineCount(stageOut)
		stats["open_ports"] = count

	case "discover":
		src := filepath.Join(p.workDir, "raw", "discover.endpoints.json")
		copyFile(src, stageOut)
		count := merge.LineCount(src)
		stats["endpoints"] = count
		p.logger.Infof("Discover: %d endpoints extracted", count)

	case "analyze":
		src := filepath.Join(p.workDir, "raw", "analyzer.findings.json")
		copyFile(src, stageOut)
		count := merge.LineCount(src)
		stats["findings"] = count
		p.logger.Infof("Analyze: %d findings", count)

	case "collect":
		src := filepath.Join(p.workDir, "raw", "collector.intel.json")
		copyFile(src, stageOut)
		stats["intel_generated"] = 1
		p.logger.Info("Collect: intelligence report generated")

	case "vuln":
		// Merge nuclei + activeprobe findings (both are JSON Lines)
		vulnFiles := []string{
			filepath.Join(p.workDir, "raw", "nuclei.findings.json"),
			filepath.Join(p.workDir, "raw", "activeprobe.findings.json"),
		}
		outF, outErr := os.Create(stageOut)
		if outErr == nil {
			for _, src := range vulnFiles {
				data, err := os.ReadFile(src)
				if err != nil {
					continue
				}
				outF.Write(data)
				// Ensure newline separator between files
				if len(data) > 0 && data[len(data)-1] != '\n' {
					outF.Write([]byte("\n"))
				}
			}
			outF.Close()
		}
		count := merge.LineCount(stageOut)
		stats["findings"] = count
	}

	return stats
}

func (p *Pipeline) logFunnel(stageName string, stats map[string]int) {
	switch stageName {
	case "resolve":
		if subs, ok := p.state.Summary["subdomains"]; ok {
			if alive, ok2 := stats["alive"]; ok2 && subs > 0 {
				pct := float64(alive) / float64(subs) * 100
				p.logger.Metric(fmt.Sprintf("enum→resolve: %d → %d (%.1f%% alive)", subs, alive, pct))
			}
		}
	case "probe":
		if alive, ok := p.state.Summary["alive"]; ok {
			if unique, ok2 := stats["unique_hosts"]; ok2 && alive > 0 {
				pct := float64(unique) / float64(alive) * 100
				p.logger.Metric(fmt.Sprintf("resolve→probe: %d → %d unique hosts (%.1f%% web-alive)", alive, unique, pct))
			}
		}
	case "discover":
		if urls, ok := p.state.Summary["total_urls"]; ok {
			if endpoints, ok2 := stats["endpoints"]; ok2 && urls > 0 {
				p.logger.Metric(fmt.Sprintf("crawl→discover: %d URLs → %d endpoints", urls, endpoints))
			}
		}
	}
}

func (p *Pipeline) checkDisk() error {
	// Simple check: stat the work dir filesystem
	var stat os.FileInfo
	stat, err := os.Stat(p.workDir)
	if err != nil {
		return nil // can't check, proceed
	}
	_ = stat

	// On Linux: use syscall.Statfs. On macOS: skip for now.
	// The Docker container will have proper disk checks via statfs.
	return nil
}

// ResolveRunDir finds an existing incomplete run or creates a new one.
func ResolveRunDir(outputDir, program string, resume bool) (runDir string, isResume bool) {
	if resume {
		// Look for existing incomplete run
		entries, err := os.ReadDir(outputDir)
		if err == nil {
			for i := len(entries) - 1; i >= 0; i-- {
				e := entries[i]
				if !e.IsDir() {
					continue
				}
				if len(e.Name()) > len(program) && e.Name()[:len(program)] == program {
					stateFile := filepath.Join(outputDir, e.Name(), "state.json")
					if st, err := LoadState(stateFile); err == nil && st.Status != "done" {
						return filepath.Join(outputDir, e.Name()), true
					}
				}
			}
		}
	}

	// New run
	jobID := fmt.Sprintf("%s-%s", program, time.Now().Format("20060102-150405"))
	return filepath.Join(outputDir, jobID), false
}

// FindLatestRunDir finds the most recent run for a program (any status).
func FindLatestRunDir(outputDir, program string) (string, bool) {
	entries, err := os.ReadDir(outputDir)
	if err != nil {
		return "", false
	}
	for i := len(entries) - 1; i >= 0; i-- {
		e := entries[i]
		if !e.IsDir() {
			continue
		}
		if len(e.Name()) > len(program) && e.Name()[:len(program)] == program {
			stateFile := filepath.Join(outputDir, e.Name(), "state.json")
			if _, err := LoadState(stateFile); err == nil {
				return filepath.Join(outputDir, e.Name()), true
			}
		}
	}
	return "", false
}

func copyFile(src, dst string) {
	data, err := os.ReadFile(src)
	if err != nil {
		return
	}
	os.MkdirAll(filepath.Dir(dst), 0755)
	os.WriteFile(dst, data, 0644)
}

func countFiles(dir, ext string) int {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return 0
	}
	count := 0
	for _, e := range entries {
		if !e.IsDir() {
			if ext == "" || filepath.Ext(e.Name()) == ext {
				count++
			}
		}
	}
	return count
}
