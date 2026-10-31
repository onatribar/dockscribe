package cmd

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"

	"github.com/onatribar/dockscribe/internal/registry"
	"github.com/onatribar/dockscribe/internal/suppress"
	"github.com/onatribar/dockscribe/pkg/analyzer"
	"github.com/onatribar/dockscribe/pkg/parser/dockerfile"
)

// Computes every finding regardless of --severity/--only, since --fix
// cleans up everything it safely can, then applies each fixable one on a
// single-line, non-suppressed instruction. Returns the (possibly
// unchanged) content so the caller can re-parse and report against what's
// actually on disk.
func applyFixesToFile(reg *registry.Registry, path string, original []byte, df *dockerfile.File, ctx analyzer.Context, suppressed suppress.Suppressions, out io.Writer) ([]byte, error) {
	var findings []analyzer.Finding
	for _, a := range reg.Analyzers {
		fs, err := a.Analyze(ctx)
		if err != nil {
			return original, fmt.Errorf("running %s analysis on %s: %w", a.Name(), path, err)
		}
		findings = append(findings, fs...)
	}

	byLine := map[int][]string{}
	for _, f := range findings {
		if dockerfile.IsFixableRule(f.RuleID) && !suppressed.Matches(f.Line, f.RuleID) {
			byLine[f.Line] = append(byLine[f.Line], f.RuleID)
		}
	}
	if len(byLine) == 0 {
		return original, nil
	}

	newLines := append([]string(nil), df.RawLines()...)
	var applied []string

	for line, ruleIDs := range byLine {
		instr, ok := df.InstructionAt(line)
		if !ok || !instr.IsSingleLine() {
			continue // multi-line instructions (continuations, heredocs) are never auto-fixed
		}
		cmd, args := instr.Cmd, instr.Args
		var fixedRules []string
		for _, ruleID := range ruleIDs {
			newCmd, newArgs, ok := dockerfile.FixInstruction(cmd, args, ruleID)
			if !ok {
				continue
			}
			cmd, args = newCmd, newArgs
			fixedRules = append(fixedRules, ruleID)
		}
		if len(fixedRules) == 0 {
			continue
		}
		newLines[line-1] = cmd + " " + args
		sort.Strings(fixedRules)
		applied = append(applied, fmt.Sprintf("L%d: %s", line, strings.Join(fixedRules, ", ")))
	}

	if len(applied) == 0 {
		return original, nil
	}
	sort.Strings(applied)

	newContent := []byte(strings.Join(newLines, "\n") + "\n")

	mode := os.FileMode(0o644)
	if info, err := os.Stat(path); err == nil {
		mode = info.Mode()
	}
	if err := os.WriteFile(path, newContent, mode); err != nil {
		return original, fmt.Errorf("writing fixed %s: %w", path, err)
	}

	fmt.Fprintf(out, "Fixed %s:\n", path)
	for _, line := range applied {
		fmt.Fprintf(out, "  %s\n", line)
	}
	return newContent, nil
}
