package provider

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"strconv"

	"github.com/badchars/recon0/internal/config"
)

type Naabu struct{}

func (n *Naabu) Name() string       { return "naabu" }
func (n *Naabu) Stage() string      { return "portscan" }
func (n *Naabu) OutputType() string { return "ports" }
func (n *Naabu) Check() error       { return CheckBinary("naabu") }

func (n *Naabu) Run(ctx context.Context, opts *RunOpts) (*Result, error) {
	extra := opts.Config
	jsonOut := opts.Output + ".json"

	topPorts := config.GetInt(extra, "top_ports", 1000)

	args := []string{
		"-list", opts.Input,
		"-top-ports", strconv.Itoa(topPorts),
		"-sa",
		"-ec",
		"-cdn",
		"-rate", strconv.Itoa(opts.Res.RateHeavy),
		"-json", "-o", jsonOut,
	}

	cmd := exec.CommandContext(ctx, "naabu", args...)
	errFile, err := OpenLogFile(opts.LogDir, "naabu")
	if err == nil {
		defer errFile.Close()
		cmd.Stderr = errFile
	}

	// naabu also writes plain text to stdout
	plainOut, _ := os.Create(opts.Output)
	if plainOut != nil {
		cmd.Stdout = plainOut
		defer plainOut.Close()
	}

	if err := cmd.Run(); err != nil {
		count := LineCount(opts.Output)
		return &Result{Count: count, OutputFile: opts.Output}, fmt.Errorf("naabu: %w", err)
	}

	count := LineCount(opts.Output)
	return &Result{
		Count:      count,
		OutputFile: opts.Output,
	}, nil
}

func init() { Register(&Naabu{}) }
