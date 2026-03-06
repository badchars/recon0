package provider

import (
	"context"
	"fmt"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/badchars/recon0/internal/config"
)

type Nuclei struct{}

func (n *Nuclei) Name() string       { return "nuclei" }
func (n *Nuclei) Stage() string      { return "vuln" }
func (n *Nuclei) OutputType() string { return "findings" }
func (n *Nuclei) Check() error       { return CheckBinary("nuclei") }

func (n *Nuclei) Run(ctx context.Context, opts *RunOpts) (*Result, error) {
	extra := opts.Config
	exportDir := filepath.Join(opts.WorkDir, "nuclei-export")

	severity := config.GetStringSlice(extra, "severity", []string{"medium", "high", "critical"})

	args := []string{
		"-l", opts.Input,
		"-as",                       // auto-scan: select templates by tech
		"-ss", "template-spray",
		"-nh",                       // no httpx
		"-duc",                      // disable update check
		"-severity", strings.Join(severity, ","),
		"-c", strconv.Itoa(opts.Res.ThreadsFull),
		"-bs", "500",
		"-rl", strconv.Itoa(opts.Res.RateNuclei),
		"-hbs", "10",
		"-timeout", strconv.Itoa(int(opts.Res.TimeoutScan.Seconds())),
		"-retries", "3",
		"-mhe", "1000",
		"-me", exportDir,
		"-stats",
		"-si", "30",
		"-j",
		"-o", opts.Output,
	}

	// Custom templates
	customDir := config.GetString(extra, "custom_templates", "")
	if customDir != "" {
		args = append(args, "-t", customDir)
	}

	// Exclude tags
	excludeTags := config.GetStringSlice(extra, "exclude_tags", nil)
	if len(excludeTags) > 0 {
		args = append(args, "-etags", strings.Join(excludeTags, ","))
	}

	cmd := exec.CommandContext(ctx, "nuclei", args...)
	errFile, err := OpenLogFile(opts.LogDir, "nuclei")
	if err == nil {
		defer errFile.Close()
		cmd.Stderr = errFile
	}

	if err := cmd.Run(); err != nil {
		count := LineCount(opts.Output)
		return &Result{Count: count, OutputFile: opts.Output}, fmt.Errorf("nuclei: %w", err)
	}

	count := LineCount(opts.Output)
	return &Result{
		Count:      count,
		OutputFile: opts.Output,
	}, nil
}

func init() { Register(&Nuclei{}) }
