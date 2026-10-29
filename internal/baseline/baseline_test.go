package baseline

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/onatribar/dockscribe/pkg/analyzer"
)

func tempPath(t *testing.T) string {
	t.Helper()
	return filepath.Join(t.TempDir(), "baseline.json")
}

func TestWriteThenLoadThenFilter(t *testing.T) {
	path := tempPath(t)
	byFile := map[string][]analyzer.Finding{
		"Dockerfile": {
			{RuleID: "S001", Message: "Container runs as root."},
			{RuleID: "S011", Message: "apt-get install without version pins."},
		},
	}
	if err := Write(path, byFile); err != nil {
		t.Fatalf("Write: %v", err)
	}

	b, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	current := []analyzer.Finding{
		{Line: 1, RuleID: "S001", Message: "Container runs as root."},
		{Line: 3, RuleID: "S011", Message: "apt-get install without version pins."},
	}
	got := b.Filter("Dockerfile", current)
	if len(got) != 0 {
		t.Errorf("expected no new findings for an exact baseline match, got %+v", got)
	}
}

func TestFilterReportsGenuinelyNewFindings(t *testing.T) {
	path := tempPath(t)
	byFile := map[string][]analyzer.Finding{
		"Dockerfile": {{RuleID: "S001", Message: "Container runs as root."}},
	}
	if err := Write(path, byFile); err != nil {
		t.Fatalf("Write: %v", err)
	}
	b, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	current := []analyzer.Finding{
		{Line: 1, RuleID: "S001", Message: "Container runs as root."}, // already baselined
		{Line: 5, RuleID: "S007", Message: "No HEALTHCHECK defined."}, // new
	}
	got := b.Filter("Dockerfile", current)
	if len(got) != 1 || got[0].RuleID != "S007" {
		t.Errorf("expected only the new S007 finding, got %+v", got)
	}
}

func TestFilterSurvivesLineShift(t *testing.T) {
	// The whole point: a finding baselined at one line still matches after
	// an unrelated edit pushes it to a different line, as long as the rule
	// and message are unchanged.
	path := tempPath(t)
	byFile := map[string][]analyzer.Finding{
		"Dockerfile": {{RuleID: "S007", Message: "No HEALTHCHECK defined."}},
	}
	if err := Write(path, byFile); err != nil {
		t.Fatalf("Write: %v", err)
	}
	b, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Same finding, now several lines further down after an unrelated edit.
	current := []analyzer.Finding{{Line: 12, RuleID: "S007", Message: "No HEALTHCHECK defined."}}
	if got := b.Filter("Dockerfile", current); len(got) != 0 {
		t.Errorf("expected the line-shifted finding to still match the baseline, got %+v", got)
	}
}

func TestFilterCountsRepeatedOccurrences(t *testing.T) {
	// The same message occurs twice in the baseline; a run reporting three
	// occurrences should surface exactly one as new, not zero and not
	// three.
	path := tempPath(t)
	msg := "apt-get install without version pins."
	byFile := map[string][]analyzer.Finding{
		"Dockerfile": {
			{RuleID: "S011", Message: msg},
			{RuleID: "S011", Message: msg},
		},
	}
	if err := Write(path, byFile); err != nil {
		t.Fatalf("Write: %v", err)
	}
	b, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	current := []analyzer.Finding{
		{Line: 2, RuleID: "S011", Message: msg},
		{Line: 5, RuleID: "S011", Message: msg},
		{Line: 9, RuleID: "S011", Message: msg},
	}
	got := b.Filter("Dockerfile", current)
	if len(got) != 1 {
		t.Fatalf("expected exactly 1 new occurrence beyond the 2 baselined, got %d: %+v", len(got), got)
	}
}

func TestFilterIsScopedPerFile(t *testing.T) {
	path := tempPath(t)
	byFile := map[string][]analyzer.Finding{
		"a/Dockerfile": {{RuleID: "S001", Message: "Container runs as root."}},
	}
	if err := Write(path, byFile); err != nil {
		t.Fatalf("Write: %v", err)
	}
	b, err := Load(path)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}

	// Same rule/message, but a different file - must not match.
	current := []analyzer.Finding{{Line: 1, RuleID: "S001", Message: "Container runs as root."}}
	got := b.Filter("b/Dockerfile", current)
	if len(got) != 1 {
		t.Errorf("expected the finding to be reported as new for a different file, got %+v", got)
	}
}

func TestWriteSkipsExplanationFindings(t *testing.T) {
	path := tempPath(t)
	byFile := map[string][]analyzer.Finding{
		"Dockerfile": {
			{Category: analyzer.CategoryExplanation, Message: "Base image: alpine."},
			{RuleID: "S001", Message: "Container runs as root."},
		},
	}
	if err := Write(path, byFile); err != nil {
		t.Fatalf("Write: %v", err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if n := Count(byFile); n != 1 {
		t.Errorf("Count = %d, want 1 (explanation excluded)", n)
	}
	if string(data) == "" {
		t.Fatal("expected a non-empty baseline file")
	}
}

func TestLoadMissingFile(t *testing.T) {
	if _, err := Load(filepath.Join(t.TempDir(), "does-not-exist.json")); err == nil {
		t.Error("expected an error loading a nonexistent baseline")
	}
}

func TestLoadInvalidJSON(t *testing.T) {
	path := tempPath(t)
	if err := os.WriteFile(path, []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := Load(path); err == nil {
		t.Error("expected an error loading a malformed baseline")
	}
}
