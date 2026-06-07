package performance

import (
	"github.com/onatribar/dockscribe/pkg/analyzer"
	"github.com/onatribar/dockscribe/pkg/parser"
)

// TODO: implement an initial ruleset to start off:
//
//	P001 Warning COPY . . before dependency install
//	P002 Warning package manager cache not cleaned in the same RUN layer (apt/apk/yum/dnf)
//	P003 Warning consecutive RUN instructions that could be chained (unnecessary layers)
//	P004 Info    ADD used where COPY is sufficient
//	P005 Info    no multi-stage build detected
//	P006 Warning large files/directories copied before a frequently-changing file (cache thrash)
type Analyzer struct{}

func New() *Analyzer { return &Analyzer{} }

func (a *Analyzer) Name() string { return "performance" }

func (a *Analyzer) Analyze(f parser.ParsedFile) ([]analyzer.Finding, error) {
	return nil, nil
}

