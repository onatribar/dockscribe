// Package text renders a Report as plain, newline-delimited text. No
// banners or decorative dividers - just the file summary, one section per
// finding category, "---" between sections, and a final summary line.
package text

import (
	"fmt"
	"io"
	"strings"

	"github.com/onatribar/dockscribe/pkg/analyzer"
	"github.com/onatribar/dockscribe/pkg/report"
)

const separator = "---"

// Renderer writes a Report as plain text.
type Renderer struct {
	Out io.Writer
}

// New returns a text Renderer that writes to out.
func New(out io.Writer) *Renderer {
	return &Renderer{Out: out}
}

var sections = []struct {
	title    string
	category analyzer.Category
}{
	{"EXPLANATION", analyzer.CategoryExplanation},
	{"SECURITY", analyzer.CategorySecurity},
	{"PERFORMANCE", analyzer.CategoryPerformance},
}

func (r *Renderer) Render(rep report.Report) error {
	w := r.Out

	fmt.Fprintf(w, "File: %s (%d lines, %d stage%s)\n", rep.File, rep.LineCount, rep.Stages, plural(rep.Stages))

	byCategory := groupByCategory(rep.Findings)
	for _, s := range sections {
		findings := byCategory[s.category]
		if len(findings) == 0 {
			continue
		}
		fmt.Fprintln(w)
		fmt.Fprintln(w, separator)
		fmt.Fprintln(w)
		fmt.Fprintln(w, s.title)
		for _, f := range findings {
			writeFinding(w, f)
		}
	}

	fmt.Fprintln(w)
	fmt.Fprintln(w, separator)
	fmt.Fprintln(w)
	fmt.Fprintf(w, "Summary: %s\n", summarize(rep.Findings))

	return nil
}

func writeFinding(w io.Writer, f analyzer.Finding) {
	if f.RuleID == "" {
		fmt.Fprintf(w, "L%-4d %s\n", f.Line, f.Message)
		return
	}
	fmt.Fprintf(w, "L%-4d [%s] [%s] %s\n", f.Line, f.RuleID, f.Severity, f.Message)
	for _, line := range strings.Split(f.Detail, "\n") {
		if line != "" {
			fmt.Fprintf(w, "      %s\n", line)
		}
	}
}

func groupByCategory(findings []analyzer.Finding) map[analyzer.Category][]analyzer.Finding {
	out := map[analyzer.Category][]analyzer.Finding{}
	for _, f := range findings {
		out[f.Category] = append(out[f.Category], f)
	}
	return out
}

func summarize(findings []analyzer.Finding) string {
	var errs, warns, infos int
	for _, f := range findings {
		switch f.Severity {
		case analyzer.Error:
			errs++
		case analyzer.Warning:
			warns++
		case analyzer.Info:
			infos++
		}
	}
	return fmt.Sprintf("%d error%s, %d warning%s, %d info", errs, plural(errs), warns, plural(warns), infos)
}

func plural(n int) string {
	if n == 1 {
		return ""
	}
	return "s"
}
