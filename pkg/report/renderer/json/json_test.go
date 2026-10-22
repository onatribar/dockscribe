package json

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/onatribar/dockscribe/pkg/analyzer"
	"github.com/onatribar/dockscribe/pkg/report"
)

func TestRenderProducesValidJSON(t *testing.T) {
	var buf bytes.Buffer
	rep := report.Report{
		File:      "Dockerfile",
		FileType:  "dockerfile",
		LineCount: 3,
		Stages:    1,
		Findings: []analyzer.Finding{
			{Line: 1, Severity: analyzer.Error, Category: analyzer.CategorySecurity, RuleID: "S001", Message: "runs as root"},
		},
		Score: 85,
		Grade: "B",
	}
	if err := New(&buf).Render(rep); err != nil {
		t.Fatalf("Render: %v", err)
	}

	var raw map[string]any
	if err := json.Unmarshal(buf.Bytes(), &raw); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	if raw["file"] != rep.File {
		t.Errorf("file = %v, want %v", raw["file"], rep.File)
	}
	if raw["score"] != float64(85) || raw["grade"] != "B" {
		t.Errorf("score/grade = %v/%v, want 85/B", raw["score"], raw["grade"])
	}
	findings := raw["findings"].([]any)
	if len(findings) != 1 {
		t.Fatalf("findings = %v, want 1 entry", findings)
	}
	first := findings[0].(map[string]any)
	if first["severity"] != "ERROR" {
		t.Errorf("severity = %v, want %q (Severity should marshal as its string form)", first["severity"], "ERROR")
	}
}
