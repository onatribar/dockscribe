package registry

import (
	"fmt"

	"github.com/onatribar/dockscribe/pkg/analyzer"
	composeanalyzer "github.com/onatribar/dockscribe/pkg/analyzer/compose"
	"github.com/onatribar/dockscribe/pkg/analyzer/explain"
	"github.com/onatribar/dockscribe/pkg/analyzer/performance"
	"github.com/onatribar/dockscribe/pkg/analyzer/security"
	"github.com/onatribar/dockscribe/pkg/parser"
	"github.com/onatribar/dockscribe/pkg/parser/compose"
	"github.com/onatribar/dockscribe/pkg/parser/dockerfile"
)

type Registry struct {
	Parsers   []parser.Parser
	Analyzers []analyzer.Analyzer
}

func New() *Registry {
	return &Registry{
		Parsers: []parser.Parser{
			dockerfile.New(),
			compose.New(),
		},
		Analyzers: []analyzer.Analyzer{
			explain.New(),
			security.New(),
			performance.New(),
			composeanalyzer.New(),
		},
	}
}

func (r *Registry) ParserFor(filename, typeOverride string) (parser.Parser, error) {
	if typeOverride != "" {
		for _, p := range r.Parsers {
			if fileType(p) == typeOverride {
				return p, nil
			}
		}
		return nil, fmt.Errorf("unknown --type %q: must be \"dockerfile\" or \"compose\"", typeOverride)
	}
	for _, p := range r.Parsers {
		if p.CanParse(filename) {
			return p, nil
		}
	}
	return nil, fmt.Errorf("no parser registered for %q (use --type to force one)", filename)
}

func fileType(p parser.Parser) string {
	switch p.(type) {
	case *dockerfile.Parser:
		return "dockerfile"
	case *compose.Parser:
		return "compose"
	default:
		return ""
	}
}
