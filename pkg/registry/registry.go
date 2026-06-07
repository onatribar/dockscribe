package registry

import (
	"fmt"

	"github.com/onatribar/dockscribe/pkg/analyzer"
	"github.com/onatribar/dockscribe/pkg/analyzer/explain"
	"github.com/onatribar/dockscribe/pkg/analyzer/performance"
	"github.com/onatribar/dockscribe/pkg/analyzer/security"
	"github.com/onatribar/dockscribe/pkg/parser"
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
		},
		Analyzers: []analyzer.Analyzer{
			explain.New(),
			security.New(),
			performance.New(),
		},
	}
}

// returns the first registered Parser able to handle filename
func (r *Registry) ParserFor(filename string) (parser.Parser, error) {
	for _, p := range r.Parsers {
		if p.CanParse(filename) {
			return p, nil
		}
	}
	return nil, fmt.Errorf("no parser registered for %q", filename)
}
