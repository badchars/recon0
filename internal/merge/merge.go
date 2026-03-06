package merge

import (
	"bufio"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
)

// TextDedup merges multiple text files into one, deduplicating lines.
func TextDedup(files []string, output string) (int, error) {
	os.MkdirAll(filepath.Dir(output), 0755)

	seen := make(map[string]struct{})
	var lines []string

	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(fh)
		scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				continue
			}
			if _, ok := seen[line]; !ok {
				seen[line] = struct{}{}
				lines = append(lines, line)
			}
		}
		fh.Close()
	}

	sort.Strings(lines)

	out, err := os.Create(output)
	if err != nil {
		return 0, fmt.Errorf("create output: %w", err)
	}
	defer out.Close()

	w := bufio.NewWriter(out)
	for _, l := range lines {
		fmt.Fprintln(w, l)
	}
	w.Flush()

	return len(lines), nil
}

// CappedMerge merges files with a maximum line count (prevents disk bombs).
func CappedMerge(files []string, output string, maxLines int) (int, error) {
	os.MkdirAll(filepath.Dir(output), 0755)

	seen := make(map[string]struct{})
	var lines []string

	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(fh)
		scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
		for scanner.Scan() {
			line := scanner.Text()
			if line == "" {
				continue
			}
			if _, ok := seen[line]; !ok {
				seen[line] = struct{}{}
				lines = append(lines, line)
			}
		}
		fh.Close()
	}

	sort.Strings(lines)

	if maxLines > 0 && len(lines) > maxLines {
		lines = lines[:maxLines]
	}

	out, err := os.Create(output)
	if err != nil {
		return 0, fmt.Errorf("create output: %w", err)
	}
	defer out.Close()

	w := bufio.NewWriter(out)
	for _, l := range lines {
		fmt.Fprintln(w, l)
	}
	w.Flush()

	return len(lines), nil
}

// JSONMerge concatenates JSON Lines files into a JSON array.
func JSONMerge(files []string, output string) (int, error) {
	os.MkdirAll(filepath.Dir(output), 0755)

	var items []json.RawMessage

	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			continue
		}
		scanner := bufio.NewScanner(fh)
		scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
		for scanner.Scan() {
			raw := scanner.Bytes()
			if len(raw) == 0 {
				continue
			}
			cp := make([]byte, len(raw))
			copy(cp, raw)
			items = append(items, json.RawMessage(cp))
		}
		fh.Close()
	}

	out, err := os.Create(output)
	if err != nil {
		return 0, fmt.Errorf("create output: %w", err)
	}
	defer out.Close()

	data, _ := json.Marshal(items)
	out.Write(data)

	return len(items), nil
}

// LineCount returns the number of lines in a file.
func LineCount(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()

	count := 0
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		count++
	}
	return count
}

// CountUniqueHosts reads a URL-per-line file and returns the count of unique hostnames.
func CountUniqueHosts(path string) int {
	f, err := os.Open(path)
	if err != nil {
		return 0
	}
	defer f.Close()

	hosts := make(map[string]struct{})
	scanner := bufio.NewScanner(f)
	scanner.Buffer(make([]byte, 1024*1024), 1024*1024)
	for scanner.Scan() {
		line := scanner.Text()
		if line == "" {
			continue
		}
		u, err := url.Parse(line)
		if err != nil {
			continue
		}
		host := u.Hostname()
		if host != "" {
			hosts[host] = struct{}{}
		}
	}
	return len(hosts)
}

// CollectByPattern finds all files in dir matching *.<outputType>.txt
func CollectByPattern(dir, outputType string) []string {
	pattern := filepath.Join(dir, "*."+outputType+".txt")
	matches, _ := filepath.Glob(pattern)
	return matches
}
