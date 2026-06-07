package analyzer

import (
	"strings"
	"github.com/onatribar/dockscribe/pkg/parser"
)

type Category string

const (
	CategoryExplanation Category = "explanation"
	CategorySecurity    Category = "security"
	CategoryPerformance Category = "performance"
)

// Severity to indicate how serious a Finding is
type Severity int

const (
	Info Severity = iota
	Warning
	Error
)

func (s Severity) String() string {
	switch s {
	case Info:
		return "INFO"
	case Warning:
		return "WARN"
	case Error:
		return "ERROR"
	default:
		return "UNKNOWN"
	}
}

func (s Severity) MarshalJSON() ([]byte, error) {
	return []byte(`"` + s.String() + `"`), nil
}

// ParseSeverity converts a --severity flag value into a Severity threshold.
func ParseSeverity(s string) (Severity, bool) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "info":

		return Info, true
	case "warning", "warn":
		return Warning, true
	case "error":
		return Error, true
	default:
		return Info, false
	}
}

// Finding is a single observation (explanation, warning, error, hint)
// produced by an analysis pass and attributed to a source line
type Finding struct {
	Line     int      `json:"line"`
	Severity Severity `json:"severity"`
	Category Category `json:"category"`
	RuleID   string   `json:"rule_id,omitempty"`
	Message  string   `json:"message"`
	Detail   string   `json:"detail,omitempty"`
}

// Analyzer runs one analysis pass over a ParsedFile and returns findings.
type Analyzer interface {
	Name() string
	Analyze(f parser.ParsedFile) ([]Finding, error)
}
