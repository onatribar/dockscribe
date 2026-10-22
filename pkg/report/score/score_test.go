package score

import (
	"testing"

	"github.com/onatribar/dockscribe/pkg/analyzer"
)

func TestComputeNoFindings(t *testing.T) {
	points, grade := Compute(nil)
	if points != 100 || grade != "A" {
		t.Errorf("Compute(nil) = (%d, %q), want (100, \"A\")", points, grade)
	}
}

func TestComputeIgnoresExplanations(t *testing.T) {
	findings := []analyzer.Finding{
		{Category: analyzer.CategoryExplanation, Severity: analyzer.Info},
		{Category: analyzer.CategoryExplanation, Severity: analyzer.Info},
	}
	points, grade := Compute(findings)
	if points != 100 || grade != "A" {
		t.Errorf("Compute(explanations only) = (%d, %q), want (100, \"A\")", points, grade)
	}
}

func TestComputeWeighsBySeverity(t *testing.T) {
	findings := []analyzer.Finding{
		{Category: analyzer.CategorySecurity, Severity: analyzer.Error},
	}
	points, _ := Compute(findings)
	if points != 100-errorCost {
		t.Errorf("one error: points = %d, want %d", points, 100-errorCost)
	}

	findings = []analyzer.Finding{
		{Category: analyzer.CategorySecurity, Severity: analyzer.Warning},
	}
	points, _ = Compute(findings)
	if points != 100-warningCost {
		t.Errorf("one warning: points = %d, want %d", points, 100-warningCost)
	}
}

func TestComputeFloorsAtZero(t *testing.T) {
	var findings []analyzer.Finding
	for i := 0; i < 20; i++ {
		findings = append(findings, analyzer.Finding{Category: analyzer.CategorySecurity, Severity: analyzer.Error})
	}
	points, grade := Compute(findings)
	if points != 0 {
		t.Errorf("points = %d, want 0 (floored)", points)
	}
	if grade != "F" {
		t.Errorf("grade = %q, want F", grade)
	}
}

func TestLetterGradeThresholds(t *testing.T) {
	tests := []struct {
		points int
		want   string
	}{
		{100, "A"}, {90, "A"}, {89, "B"}, {75, "B"}, {74, "C"}, {60, "C"}, {59, "D"}, {40, "D"}, {39, "F"}, {0, "F"},
	}
	for _, tt := range tests {
		if got := letterGrade(tt.points); got != tt.want {
			t.Errorf("letterGrade(%d) = %q, want %q", tt.points, got, tt.want)
		}
	}
}
