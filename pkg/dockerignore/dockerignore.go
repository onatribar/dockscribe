package dockerignore

import (
	"bufio"
	"bytes"
	"strings"
)

// returns the non-comment, non-blank patterns from a .dockerignore file's content
func Parse(content []byte) []string {
	var patterns []string
	scanner := bufio.NewScanner(bytes.NewReader(content))
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		patterns = append(patterns, line)
	}
	return patterns
}

// Deliberately loose substring matching ("did the author ever think
// about this path?"), not an emulation of Docker's actual ignore-glob
// engine.
func Excludes(patterns []string, substr string) bool {
	substr = strings.ToLower(substr)
	for _, p := range patterns {
		if strings.HasPrefix(p, "!") {
			continue // negation (re-include)
		}

		lp := strings.ToLower(strings.Trim(p, "*/"))
		if lp == "" {
			continue
		}
		if strings.Contains(substr, lp) || strings.Contains(lp, substr) {
			return true
		}
	}
	return false
}
