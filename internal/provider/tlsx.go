package provider

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
)

type Tlsx struct{}

func (t *Tlsx) Name() string       { return "tlsx" }
func (t *Tlsx) Stage() string      { return "probe" }
func (t *Tlsx) OutputType() string { return "tls" }
func (t *Tlsx) Check() error       { return CheckBinary("tlsx") }

func (t *Tlsx) Run(ctx context.Context, opts *RunOpts) (*Result, error) {
	jsonOut := opts.Output + ".json"

	// Single pass: tlsx returns SAN, CN, org, version, cipher in default JSON
	args := []string{
		"-l", opts.Input,
		"-p", "443",
		"-c", strconv.Itoa(opts.Res.ThreadsHeavy),
		"-timeout", strconv.Itoa(int(opts.Res.TimeoutHTTP.Seconds())),
		"-json", "-o", jsonOut,
	}

	cmd := exec.CommandContext(ctx, "tlsx", args...)
	errFile, err := OpenLogFile(opts.LogDir, "tlsx")
	if err == nil {
		defer errFile.Close()
		cmd.Stderr = errFile
	}

	if err := cmd.Run(); err != nil {
		count := LineCount(jsonOut)
		return &Result{Count: count, OutputFile: jsonOut}, fmt.Errorf("tlsx: %w", err)
	}

	count := LineCount(jsonOut)
	return &Result{
		Count:      count,
		OutputFile: jsonOut,
	}, nil
}

func init() { Register(&Tlsx{}) }
