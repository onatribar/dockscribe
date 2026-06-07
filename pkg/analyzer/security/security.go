package security

import (
	"github.com/onatribar/dockscribe/pkg/analyzer"
	"github.com/onatribar/dockscribe/pkg/parser"
)

// TODO: implement the initial ruleset, examples like so:
//
//	S001 Error   running as root
//	S002 Warning ADD used with a URL; prefer COPY or curl/wget
//	S003 Warning secrets passed via ARG/ENV (key patterns like *_KEY, *_SECRET, *_TOKEN, *_PASSWORD, ...)
//	S004 Warning COPY --chown missing on sensitive directories
//	S005 Info    base image pinned to a mutable tag
//	S006 Warning curl | bash pattern detected in a RUN instruction
//	S007 Info    no HEALTHCHECK defined
type Analyzer struct{}

func New() *Analyzer { return &Analyzer{} }

func (a *Analyzer) Name() string { return "security" }

func (a *Analyzer) Analyze(f parser.ParsedFile) ([]analyzer.Finding, error) {
	return nil, nil
}

