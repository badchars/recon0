package log

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sync"
	"time"
)

// Level represents log severity.
type Level int

const (
	DEBUG    Level = iota
	INFO
	WARN
	ERROR
	STAGE    // stage banners
	PROVIDER // provider messages
	METRIC   // pipeline metrics
)

var levelNames = map[Level]string{
	DEBUG: "DEBUG", INFO: "INFO", WARN: "WARN", ERROR: "ERROR",
	STAGE: "STAGE", PROVIDER: "PROV", METRIC: "METRIC",
}

var levelColors = map[Level]string{
	DEBUG: "\033[90m",   // gray
	INFO:  "\033[36m",   // cyan
	WARN:  "\033[33m",   // yellow
	ERROR: "\033[31m",   // red
	STAGE: "\033[35;1m", // bold magenta
	PROVIDER: "\033[32m", // green
	METRIC:   "\033[34m", // blue
}

const colorReset = "\033[0m"

// Entry is a structured log record written to the JSON log file.
type Entry struct {
	Time     string         `json:"time"`
	Level    string         `json:"level"`
	Stage    string         `json:"stage,omitempty"`
	Provider string         `json:"provider,omitempty"`
	Msg      string         `json:"msg"`
	Fields   map[string]any `json:"fields,omitempty"`
}

// Logger is a multi-output structured logger.
type Logger struct {
	mu          sync.Mutex
	console     io.Writer
	file        io.Writer
	fileCloser  io.Closer
	minLevel    Level
	useColor    bool
	currentStage string
}

// New creates a logger. format: "color"|"plain"|"json". logPath: "" to skip file output.
func New(level Level, format string, logPath string) *Logger {
	l := &Logger{
		console:  os.Stderr,
		minLevel: level,
		useColor: format == "color",
	}

	if logPath != "" {
		f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0644)
		if err == nil {
			l.file = f
			l.fileCloser = f
		}
	}

	return l
}

// Close flushes and closes the log file.
func (l *Logger) Close() {
	if l.fileCloser != nil {
		l.fileCloser.Close()
	}
}

// SetStage sets the current stage context for subsequent log calls.
func (l *Logger) SetStage(name string) {
	l.mu.Lock()
	l.currentStage = name
	l.mu.Unlock()
}

func (l *Logger) log(level Level, stage, provider, msg string, fields map[string]any) {
	if level < l.minLevel && level < STAGE {
		return
	}

	now := time.Now().UTC()
	ts := now.Format("2006-01-02 15:04:05")

	l.mu.Lock()
	defer l.mu.Unlock()

	if stage == "" {
		stage = l.currentStage
	}

	// Console output
	levelStr := levelNames[level]
	if l.useColor {
		color := levelColors[level]
		if provider != "" {
			fmt.Fprintf(l.console, "%s[%s]%s %s[%s]%s %s\n",
				"\033[90m", ts, colorReset,
				color, provider, colorReset,
				msg)
		} else {
			fmt.Fprintf(l.console, "%s[%s]%s %s[%s]%s %s\n",
				"\033[90m", ts, colorReset,
				color, levelStr, colorReset,
				msg)
		}
	} else {
		if provider != "" {
			fmt.Fprintf(l.console, "[%s] [%s] %s\n", ts, provider, msg)
		} else {
			fmt.Fprintf(l.console, "[%s] [%s] %s\n", ts, levelStr, msg)
		}
	}

	// JSON file output
	if l.file != nil {
		entry := Entry{
			Time:     now.Format(time.RFC3339),
			Level:    levelStr,
			Stage:    stage,
			Provider: provider,
			Msg:      msg,
			Fields:   fields,
		}
		data, _ := json.Marshal(entry)
		fmt.Fprintf(l.file, "%s\n", data)
	}
}

// Debug logs a debug message.
func (l *Logger) Debug(msg string, fields ...map[string]any) {
	l.log(DEBUG, "", "", msg, mergeFields(fields))
}

// Info logs an info message.
func (l *Logger) Info(msg string, fields ...map[string]any) {
	l.log(INFO, "", "", msg, mergeFields(fields))
}

// Warn logs a warning.
func (l *Logger) Warn(msg string, fields ...map[string]any) {
	l.log(WARN, "", "", msg, mergeFields(fields))
}

// Error logs an error.
func (l *Logger) Error(msg string, fields ...map[string]any) {
	l.log(ERROR, "", "", msg, mergeFields(fields))
}

// Stage logs a stage banner.
func (l *Logger) Stage(name string) {
	l.SetStage(name)
	l.log(STAGE, name, "", fmt.Sprintf("════════════ %s ════════════", name), nil)
}

// Provider logs a provider-scoped message.
func (l *Logger) Provider(name, msg string, fields ...map[string]any) {
	l.log(PROVIDER, "", name, msg, mergeFields(fields))
}

// Metric logs a pipeline metric.
func (l *Logger) Metric(msg string, fields ...map[string]any) {
	l.log(METRIC, "", "", msg, mergeFields(fields))
}

// Infof logs a formatted info message.
func (l *Logger) Infof(format string, args ...any) {
	l.Info(fmt.Sprintf(format, args...))
}

// Warnf logs a formatted warning.
func (l *Logger) Warnf(format string, args ...any) {
	l.Warn(fmt.Sprintf(format, args...))
}

// Errorf logs a formatted error.
func (l *Logger) Errorf(format string, args ...any) {
	l.Error(fmt.Sprintf(format, args...))
}

func mergeFields(fields []map[string]any) map[string]any {
	if len(fields) == 0 {
		return nil
	}
	return fields[0]
}
