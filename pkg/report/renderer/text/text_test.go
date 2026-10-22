package text

import (
	"bytes"
	"strings"
	"testing"

	"github.com/onatribar/dockscribe/pkg/analyzer"
	"github.com/onatribar/dockscribe/pkg/report"
)

func TestRenderIncludesFileHeaderAndSummary(t *testing.T) {
	var buf bytes.Buffer
	rep := report.Report{
		File:      "Dockerfile",
		FileType:  "dockerfile",
		LineCount: 10,
		Stages:    1,
		Findings: []analyzer.Finding{
			{Line: 1, Severity: analyzer.Error, Category: analyzer.CategorySecurity, RuleID: "S001", Message: "runs as root", Detail: "add USER"},
			{Line: 2, Severity: analyzer.Info, Category: analyzer.CategoryExplanation, Message: "base image explanation"},
		},
		Score: 85,
		Grade: "B",
	}
	if err := New(&buf).Render(rep); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := buf.String()

	for _, want := range []string{"Dockerfile", "EXPLANATION", "SECURITY", "S001", "runs as root", "add USER", "Summary: 1 error, 0 warnings, 1 info", "Score: 85/100 (B)"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q; got:\n%s", want, out)
		}
	}
}

func TestRenderSkipsEmptyCategories(t *testing.T) {
	var buf bytes.Buffer
	rep := report.Report{
		File: "Dockerfile",
		Findings: []analyzer.Finding{
			{Line: 1, Severity: analyzer.Warning, Category: analyzer.CategoryPerformance, RuleID: "P001", Message: "cache busted"},
		},
	}
	if err := New(&buf).Render(rep); err != nil {
		t.Fatalf("Render: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "SECURITY") {
		t.Errorf("expected no SECURITY section when there are no security findings; got:\n%s", out)
	}
	if !strings.Contains(out, "PERFORMANCE") {
		t.Errorf("expected a PERFORMANCE section; got:\n%s", out)
	}
}

func TestRenderNoFindings(t *testing.T) {
	var buf bytes.Buffer
	rep := report.Report{File: "Dockerfile", LineCount: 5, Stages: 1}
	if err := New(&buf).Render(rep); err != nil {
		t.Fatalf("Render: %v", err)
	}
	if !strings.Contains(buf.String(), "Summary: 0 errors, 0 warnings, 0 info") {
		t.Errorf("expected a zero-finding summary line; got:\n%s", buf.String())
	}
}
