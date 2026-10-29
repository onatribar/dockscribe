package baseline

import (
	"encoding/json"
	"fmt"
	"os"

	"github.com/onatribar/dockscribe/pkg/analyzer"
)

const schemaVersion = 1

type entry struct {
	File    string `json:"file"`
	RuleID  string `json:"rule_id"`
	Message string `json:"message"`
}

type file struct {
	Version  int     `json:"version"`
	Findings []entry `json:"findings"`
}

type key struct {
	file    string
	ruleID  string
	message string
}

type Baseline struct {
	remaining map[key]int
}

func Load(path string) (*Baseline, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading baseline %s: %w (run with --write-baseline first)", path, err)
	}
	var f file
	if err := json.Unmarshal(data, &f); err != nil {
		return nil, fmt.Errorf("parsing baseline %s: %w", path, err)
	}
	b := &Baseline{remaining: map[key]int{}}
	for _, e := range f.Findings {
		b.remaining[key{e.File, e.RuleID, e.Message}]++
	}
	return b, nil
}

func (b *Baseline) Filter(path string, findings []analyzer.Finding) []analyzer.Finding {
	var out []analyzer.Finding
	for _, f := range findings {
		k := key{path, f.RuleID, f.Message}
		if b.remaining[k] > 0 {
			b.remaining[k]--
			continue
		}
		out = append(out, f)
	}
	return out
}

func Write(path string, findingsByFile map[string][]analyzer.Finding) error {
	var out file
	out.Version = schemaVersion
	for _, filePath := range analyzer.SortedKeys(findingsByFile) {
		for _, f := range findingsByFile[filePath] {
			if f.RuleID == "" {
				continue
			}
			out.Findings = append(out.Findings, entry{File: filePath, RuleID: f.RuleID, Message: f.Message})
		}
	}

	data, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		return fmt.Errorf("encoding baseline: %w", err)
	}
	data = append(data, '\n')
	if err := os.WriteFile(path, data, 0o644); err != nil {
		return fmt.Errorf("writing baseline %s: %w", path, err)
	}
	return nil
}

func Count(findingsByFile map[string][]analyzer.Finding) int {
	n := 0
	for _, findings := range findingsByFile {
		for _, f := range findings {
			if f.RuleID != "" {
				n++
			}
		}
	}
	return n
}