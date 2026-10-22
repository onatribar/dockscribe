package score

import "github.com/onatribar/dockscribe/pkg/analyzer"

const (
	errorCost   = 15
	warningCost = 5
	infoCost    = 1
)

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
