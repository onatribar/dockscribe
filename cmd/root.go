package cmd

import (
	"fmt"

	"github.com/spf13/cobra"

	"github.com/onatribar/dockscribe/pkg/analyzer"
	"github.com/onatribar/dockscribe/pkg/loader"
	"github.com/onatribar/dockscribe/pkg/parser"
	"github.com/onatribar/dockscribe/pkg/registry"
	"github.com/onatribar/dockscribe/pkg/report"
	jsonrenderer "github.com/onatribar/dockscribe/pkg/report/renderer/json"
	textrenderer "github.com/onatribar/dockscribe/pkg/report/renderer/text"
)

var (
	formatFlag    string
	severityFlag  string
	noExplainFlag bool
	onlyFlag      string
)

var rootCmd = &cobra.Command{
	Use:   "dockscribe [file...]",
	Short: "Explain and audit container configuration files",
	Long: "dockscribe reads container configuration files (starting with Dockerfiles) and\n" +
		"produces human-readable explanations, all while flagging security vulnerabilities and\n" +
		"performance issues using deterministic analysis.\n\n" +
		"If no files are given, it analyses ./Dockerfile.",
	Args: cobra.ArbitraryArgs,
	RunE: run,
}

func init() {
	rootCmd.Flags().StringVar(&formatFlag, "format", "text", `output format: "text" or "json"`)
	rootCmd.Flags().StringVar(&severityFlag, "severity", "info", `minimum severity to report: "info", "warning", or "error"`)
	rootCmd.Flags().BoolVar(&noExplainFlag, "no-explain", false, "skip the explanation pass; show only findings")
	rootCmd.Flags().StringVar(&onlyFlag, "only", "", `run a single analysis category: "security" or "performance"`)
}

func Execute() error {
	return rootCmd.Execute()
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
	for _, path := range files {
		if err := analyzeFile(reg, path, threshold, only, render); err != nil {
			return err
		}
	}
	return nil
}

func analyzeFile(reg *registry.Registry, path string, threshold analyzer.Severity, only analyzer.Category, render func(report.Report) error) error {
	f, err := loader.Load(path)
	if err != nil {
		return err
	}

	p, err := reg.ParserFor(path)
	if err != nil {
		return err
	}

	parsed, err := p.Parse(f.Content)
	if err != nil {
		return fmt.Errorf("parsing %s: %w", path, err)
	}

	var findings []analyzer.Finding
	for _, a := range reg.Analyzers {
		fs, err := a.Analyze(parsed)
		if err != nil {
			return fmt.Errorf("running %s analysis on %s: %w", a.Name(), path, err)
		}
		for _, finding := range fs {
			if !categoryWanted(finding.Category, only) || finding.Severity < threshold {
				continue
			}
			findings = append(findings, finding)
		}
	}

	rep := report.Report{
		File:      path,
		FileType:  parsed.FileType(),
		LineCount: len(parsed.RawLines()),
		Stages:    stageCount(parsed),
		Findings:  findings,
	}
	return render(rep)
}

// categoryWanted reports whether a finding's category should be included 
// (planned: security & performance)
// --no-explain ought to drops explanations entirely)
// --only to restrict output to a single category
func categoryWanted(category, only analyzer.Category) bool {
	if category == analyzer.CategoryExplanation {
		return !noExplainFlag && only == ""
	}
	return only == "" || only == category
}

// stageCounter is satisfied by ParsedFile
// reports the nr of build stages
type stageCounter interface {
	StageCount() int
}

func stageCount(f parser.ParsedFile) int {
	if sc, ok := f.(stageCounter); ok {
		return sc.StageCount()
	}
	return 0
}
