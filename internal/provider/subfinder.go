package provider

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"

	"github.com/badchars/recon0/internal/config"
)

type Subfinder struct{}

func (s *Subfinder) Name() string       { return "subfinder" }
func (s *Subfinder) Stage() string      { return "enum" }
func (s *Subfinder) OutputType() string { return "subdomains" }
func (s *Subfinder) Check() error       { return CheckBinary("subfinder") }

func (s *Subfinder) Run(ctx context.Context, opts *RunOpts) (*Result, error) {
	extra := opts.Config
	timeout := config.GetInt(extra, "timeout", 30) // minutes, subfinder default

	args := []string{
		"-dL", opts.Input,
		"-all",
		"-recursive",
		"-t", strconv.Itoa(opts.Res.ThreadsHeavy),
		"-timeout", strconv.Itoa(timeout),
		"-o", opts.Output,
	}

	if config.GetBool(extra, "silent", true) {
		args = append(args, "-silent")
	}

	cmd := exec.CommandContext(ctx, "subfinder", args...)
	errFile, err := OpenLogFile(opts.LogDir, "subfinder")
	if err == nil {
		defer errFile.Close()
		cmd.Stderr = errFile
	}

	if err := cmd.Run(); err != nil {
		return &Result{OutputFile: opts.Output}, fmt.Errorf("subfinder: %w", err)
	}

	count := LineCount(opts.Output)
	return &Result{
		Count:      count,
		OutputFile: opts.Output,
	}, nil
}

func init() { Register(&Subfinder{}) }
