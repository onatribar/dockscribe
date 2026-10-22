package report

import "github.com/onatribar/dockscribe/pkg/analyzer"

type Report struct {
	File      string             `json:"file"`
	FileType  string             `json:"file_type"`
	LineCount int                `json:"line_count"`
	Stages    int                `json:"stages"`
	Findings  []analyzer.Finding `json:"findings"`
	Score     int                `json:"score"` // 0-100, derived from Findings; see pkg/report/score
	Grade     string             `json:"grade"` // letter grade for Score, e.g. "A"
}
