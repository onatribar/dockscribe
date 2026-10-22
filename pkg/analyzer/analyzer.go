package analyzer

import (
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/onatribar/dockscribe/pkg/parser"
)

type Category string

const (
	CategoryExplanation Category = "explanation"
	CategorySecurity    Category = "security"
	CategoryPerformance Category = "performance"
	// Findings about suppression itself (e.g. an unused ignore comment) - filtered by --only but not a selectable --only value.
	CategorySuppression Category = "suppression"
)

// Ordered Info < Warning < Error. Error: certain and unambiguous (build fails, or a credential is provably baked in). Warning: a real problem that could have a legitimate reason, or is inherently a heuristic. Info: best-practice guidance where nothing is actually wrong yet.
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

type Finding struct {
	Line     int      `json:"line"`
	Severity Severity `json:"severity"`
	Category Category `json:"category"`
	RuleID   string   `json:"rule_id,omitempty"`
	Message  string   `json:"message"`
	Detail   string   `json:"detail,omitempty"`
}

// Dir lets checks read sibling files, e.g. .dockerignore.
type Context struct {
	File parser.ParsedFile
	Dir  string // "" if unknown
}

// ok is false if Dir is unset or the file can't be read.
func (c Context) ReadSibling(name string) (content []byte, ok bool) {
	if c.Dir == "" {
		return nil, false
	}
	data, err := os.ReadFile(filepath.Join(c.Dir, name))
	if err != nil {
		return nil, false
	}
	return data, true
}

type Analyzer interface {
	Name() string
	Analyze(ctx Context) ([]Finding, error)
}

// Go randomizes map iteration on purpose; any check generating findings
// from a map needs this first, or output order would vary between runs.
func SortedKeys[V any](m map[string]V) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}
