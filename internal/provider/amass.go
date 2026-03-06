package provider

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"

	"github.com/badchars/recon0/internal/config"
)

type Amass struct{}

func (a *Amass) Name() string       { return "amass" }
func (a *Amass) Stage() string      { return "enum" }
func (a *Amass) OutputType() string { return "subdomains" }
func (a *Amass) Check() error       { return CheckBinary("amass") }

func (a *Amass) Run(ctx context.Context, opts *RunOpts) (*Result, error) {
	extra := opts.Config
	timeout := config.GetInt(extra, "timeout", 30) // minutes

	args := []string{
		"enum",
		"-passive",
		"-df", opts.Input,
		"-timeout", strconv.Itoa(timeout),
		"-o", opts.Output,
	}

	if config.GetBool(extra, "silent", true) {
		args = append(args, "-silent")
	}

	cmd := exec.CommandContext(ctx, "amass", args...)
	errFile, err := OpenLogFile(opts.LogDir, "amass")
	if err == nil {
		defer errFile.Close()
		cmd.Stderr = errFile
	}

	if err := cmd.Run(); err != nil {
		return &Result{OutputFile: opts.Output}, fmt.Errorf("amass: %w", err)
	}

	count := LineCount(opts.Output)
	return &Result{
		Count:      count,
		OutputFile: opts.Output,
	}, nil
}

func init() { Register(&Amass{}) }
