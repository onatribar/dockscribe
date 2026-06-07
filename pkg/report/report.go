package report

import "github.com/onatribar/dockscribe/pkg/analyzer"

type Report struct {
	File      string             `json:"file"`
	FileType  string             `json:"file_type"`
	LineCount int                `json:"line_count"`
	Stages    int                `json:"stages"`
	Findings  []analyzer.Finding `json:"findings"`
}
