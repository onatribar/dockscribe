// Package score turns findings into a 0-100 number and letter grade - a
// coarse, fully-explainable heuristic for an at-a-glance signal, not a
// substitute for reading the findings.
package score

import "github.com/onatribar/dockscribe/pkg/analyzer"

// Point cost per finding, by severity. Explanation findings (which have no
// severity signal - they're always Info but aren't "issues") are excluded
// entirely rather than assigned a weight.
const (
	errorCost   = 15
	warningCost = 5
	infoCost    = 1
)

// Reflects exactly the findings passed in, excluding explanations, so a
// filtered caller (--severity, --only) gets a matching score.
func Compute(findings []analyzer.Finding) (points int, grade string) {
	cost := 0
	for _, f := range findings {
		if f.Category == analyzer.CategoryExplanation {
			continue
		}
		switch f.Severity {
		case analyzer.Error:
			cost += errorCost
		case analyzer.Warning:
			cost += warningCost
		case analyzer.Info:
			cost += infoCost
		}
	}
	points = 100 - cost
	if points < 0 {
		points = 0
	}
	return points, letterGrade(points)
}

func letterGrade(points int) string {
	switch {
	case points >= 90:
		return "A"
	case points >= 75:
		return "B"
	case points >= 60:
		return "C"
	case points >= 40:
		return "D"
	default:
		return "F"
	}
}
