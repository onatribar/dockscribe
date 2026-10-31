package cmd

import (
	"bytes"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"

	"github.com/onatribar/dockscribe/internal/baseline"
	"github.com/onatribar/dockscribe/internal/loader"
	"github.com/onatribar/dockscribe/internal/registry"
	"github.com/onatribar/dockscribe/internal/suppress"
	"github.com/onatribar/dockscribe/pkg/analyzer"
	"github.com/onatribar/dockscribe/pkg/parser"
	"github.com/onatribar/dockscribe/pkg/parser/dockerfile"
	"github.com/onatribar/dockscribe/pkg/report"
	jsonrenderer "github.com/onatribar/dockscribe/pkg/report/renderer/json"
	textrenderer "github.com/onatribar/dockscribe/pkg/report/renderer/text"
	"github.com/onatribar/dockscribe/pkg/report/score"
)

var (
	formatFlag        string
	severityFlag      string
	noExplainFlag     bool
	onlyFlag          string
	failOnFlag        string
	fixFlag           bool
	typeFlag          string
	baselineFlag      string
	writeBaselineFlag string
)

// Distinguishes "ran fine, found gating issues" (1) from "ran fine,
// nothing gates" (0); a hard execution error is separate - see Execute.
var exitCode int

var rootCmd = &cobra.Command{
	Use:     "dockscribe [file or directory...]",
	Version: fullVersion(),
	Short:   "Explain and audit container configuration files",
	Long: "dockscribe reads Dockerfiles and Compose files and produces human-readable\n" +
		"explanations, all while flagging security vulnerabilities and performance issues\n" +
		"using deterministic analysis.\n\n" +
		"If no files are given, it analyses ./Dockerfile. A directory argument is scanned\n" +
		"recursively for every Dockerfile/Compose file in it.",
	Args: cobra.ArbitraryArgs,
	RunE: run,
}

func init() {
	rootCmd.Flags().StringVar(&formatFlag, "format", "text", `output format: "text" or "json"`)
	rootCmd.Flags().StringVar(&severityFlag, "severity", "info", `minimum severity to report: "info", "warning", or "error"`)
	rootCmd.Flags().BoolVar(&noExplainFlag, "no-explain", false, "skip the explanation pass; show only findings")
	rootCmd.Flags().StringVar(&onlyFlag, "only", "", `run a single analysis category: "security" or "performance"`)
	rootCmd.Flags().StringVar(&failOnFlag, "fail-on", "error", `minimum severity that makes the process exit non-zero: "never", "info", "warning", or "error"`)
	rootCmd.Flags().BoolVar(&fixFlag, "fix", false, "auto-fix a safe subset of findings in place, then report what's left")
	rootCmd.Flags().StringVar(&typeFlag, "type", "", `force file type instead of guessing from filename: "dockerfile" or "compose"`)
	rootCmd.Flags().StringVar(&baselineFlag, "baseline", "", "only report findings not already recorded in this baseline file")
	rootCmd.Flags().StringVar(&writeBaselineFlag, "write-baseline", "", "write every current finding to this file as a new baseline, then exit 0")
}

// Execute returns 0 if nothing met --fail-on, 1 if something did
// (CI-gating), or 2 if the tool itself failed - "your Dockerfile has a
// problem" vs. "dockscribe couldn't even run."
func Execute() int {
	exitCode = 0
	if err := rootCmd.Execute(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 2
	}
	return exitCode
}

func run(cmd *cobra.Command, args []string) error {
	threshold, ok := analyzer.ParseSeverity(severityFlag)
	if !ok {
		return fmt.Errorf(`invalid --severity %q: must be "info", "warning", or "error"`, severityFlag)
	}
	only := analyzer.Category(onlyFlag)
	if onlyFlag != "" && only != analyzer.CategorySecurity && only != analyzer.CategoryPerformance {
		return fmt.Errorf(`invalid --only %q: must be "security" or "performance"`, onlyFlag)
	}
	failOnNever, failOnThreshold, ok := parseFailOn(failOnFlag)
	if !ok {
		return fmt.Errorf(`invalid --fail-on %q: must be "never", "info", "warning", or "error"`, failOnFlag)
	}
	if baselineFlag != "" && writeBaselineFlag != "" {
		return fmt.Errorf("--baseline and --write-baseline can't be used together - writing a baseline while also comparing against it doesn't mean anything")
	}
	var bl *baseline.Baseline
	if baselineFlag != "" {
		loaded, err := baseline.Load(baselineFlag)
		if err != nil {
			return err
		}
		bl = loaded
	}

	var render func(report.Report) error
	switch formatFlag {
	case "text":
		render = textrenderer.New(cmd.OutOrStdout()).Render
	case "json":
		render = jsonrenderer.New(cmd.OutOrStdout()).Render
	default:
		return fmt.Errorf(`invalid --format %q: must be "text" or "json"`, formatFlag)
	}

	files := args
	if len(files) == 0 {
		files = []string{"Dockerfile"}
	}

	reg := registry.New()
	files, err := expandPaths(reg, files)
	if err != nil {
		return err
	}
	if len(files) == 0 {
		return fmt.Errorf("no Dockerfile or Compose files found")
	}

	// Deliberately sequential, not goroutines-per-file: one file costs
	// ~100µs end-to-end (see BenchmarkAnalyze* in
	// internal/registry/registry_bench_test.go), so concurrency wouldn't be
	// observable but would cost real complexity (ordered output, --fix's
	// file writes racing each other). Revisit only if profiling a real
	// large batch shows this loop as the bottleneck.
	findingsByFile := map[string][]analyzer.Finding{}
	for _, path := range files {
		findings, exceeded, err := analyzeFile(reg, path, threshold, only, render, fixFlag, typeFlag, bl, cmd.ErrOrStderr())
		if err != nil {
			return err
		}
		if writeBaselineFlag != "" {
			findingsByFile[path] = findings
		}
		if !failOnNever && exceeded >= failOnThreshold {
			exitCode = 1
		}
	}

	if writeBaselineFlag != "" {
		if err := baseline.Write(writeBaselineFlag, findingsByFile); err != nil {
			return err
		}
		fmt.Fprintf(cmd.ErrOrStderr(), "Wrote baseline (%d finding(s) across %d file(s)): %s\n",
			baseline.Count(findingsByFile), len(files), writeBaselineFlag)
		exitCode = 0 // writing a baseline accepts the current state; it never gates
	}
	return nil
}

// Skipped as common non-source trees that would otherwise slow a scan for
// no benefit.
var heavyDirs = map[string]bool{
	".git": true, "node_modules": true, "vendor": true, ".venv": true, "__pycache__": true,
}

// Non-directory arguments pass through unchanged - loader.Load gives a
// clearer error for a missing file than Stat would here.
func expandPaths(reg *registry.Registry, args []string) ([]string, error) {
	var out []string
	for _, arg := range args {
		info, err := os.Stat(arg)
		if err != nil || !info.IsDir() {
			out = append(out, arg)
			continue
		}
		err = filepath.WalkDir(arg, func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() {
				if path != arg && heavyDirs[d.Name()] {
					return filepath.SkipDir
				}
				return nil
			}
			for _, p := range reg.Parsers {
				if p.CanParse(path) {
					out = append(out, path)
					break
				}
			}
			return nil
		})
		if err != nil {
			return nil, fmt.Errorf("scanning %s: %w", arg, err)
		}
	}
	return out, nil
}

// "never" is a sentinel meaning no finding should ever trigger a non-zero
// exit; ok is false for anything else analyzer.ParseSeverity doesn't
// already accept.
func parseFailOn(s string) (never bool, threshold analyzer.Severity, ok bool) {
	if strings.EqualFold(strings.TrimSpace(s), "never") {
		return true, 0, true
	}
	threshold, ok = analyzer.ParseSeverity(s)
	return false, threshold, ok
}

// Highest severity is -1 when there are no findings. If fix is true,
// every safely-fixable finding is applied first and reported on the fixed
// content. Callers aggregating for --write-baseline should pass bl as
// nil, since a baseline is built pre-filtering.
func analyzeFile(reg *registry.Registry, path string, threshold analyzer.Severity, only analyzer.Category, render func(report.Report) error, fix bool, typeOverride string, bl *baseline.Baseline, fixOut io.Writer) ([]analyzer.Finding, analyzer.Severity, error) {
	highest := analyzer.Severity(-1) // no findings

	f, err := loader.Load(path)
	if err != nil {
		return nil, highest, err
	}

	p, err := reg.ParserFor(path, typeOverride)
	if err != nil {
		return nil, highest, err
	}

	parsed, err := p.Parse(f.Content)
	if err != nil {
		return nil, highest, fmt.Errorf("parsing %s: %w", path, err)
	}

	// Suppression comments sit on their own line, so a fix rewriting the
	// target line's text never shifts line numbers - safe to compute once
	// here and reuse after a fix.
	suppressed := suppress.Parse(parsed.RawLines())

	ctx := analyzer.Context{File: parsed, Dir: filepath.Dir(path)}

	if fix {
		if df, ok := parsed.(*dockerfile.File); ok {
			fixedContent, err := applyFixesToFile(reg, path, f.Content, df, ctx, suppressed, fixOut)
			if err != nil {
				return nil, highest, err
			}
			if !bytes.Equal(fixedContent, f.Content) {
				parsed, err = p.Parse(fixedContent)
				if err != nil {
					return nil, highest, fmt.Errorf("re-parsing fixed %s: %w", path, err)
				}
				ctx = analyzer.Context{File: parsed, Dir: filepath.Dir(path)}
			}
		}
	}

	var allFindings []analyzer.Finding
	for _, a := range reg.Analyzers {
		fs, err := a.Analyze(ctx)
		if err != nil {
			return nil, highest, fmt.Errorf("running %s analysis on %s: %w", a.Name(), path, err)
		}
		allFindings = append(allFindings, fs...)
	}
	// Computed against every finding an analysis pass actually produced,
	// before the display filtering below - whether a suppression matched
	// something is independent of what --severity/--only chose to show.
	allFindings = append(allFindings, suppressed.UnusedFindings(allFindings)...)

	var findings []analyzer.Finding
	for _, finding := range allFindings {
		if !categoryWanted(finding.Category, only) || finding.Severity < threshold || suppressed.Matches(finding.Line, finding.RuleID) {
			continue
		}
		findings = append(findings, finding)
	}
	if bl != nil {
		findings = bl.Filter(path, findings)
	}
	for _, finding := range findings {
		if finding.Severity > highest {
			highest = finding.Severity
		}
	}

	points, grade := score.Compute(findings)
	rep := report.Report{
		File:      path,
		FileType:  parsed.FileType(),
		LineCount: len(parsed.RawLines()),
		Stages:    stageCount(parsed),
		Findings:  findings,
		Score:     points,
		Grade:     grade,
	}
	return findings, highest, render(rep)
}

func categoryWanted(category, only analyzer.Category) bool {
	if category == analyzer.CategoryExplanation {
		return !noExplainFlag && only == ""
	}
	return only == "" || only == category
}

// Only dockerfile.File implements this today; everything else reports 0 stages.
type stageCounter interface {
	StageCount() int
}

func stageCount(f parser.ParsedFile) int {
	if sc, ok := f.(stageCounter); ok {
		return sc.StageCount()
	}
	return 0
}
