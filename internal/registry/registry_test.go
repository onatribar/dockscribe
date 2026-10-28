package registry

import (
	"os"
	"path/filepath"
	"testing"
	"github.com/onatribar/dockscribe/pkg/analyzer"
)

func ruleIDs(t *testing.T, path string) map[string]bool {
	t.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v", path, err)
	}

	reg := New()
	p, err := reg.ParserFor(path, "")
	if err != nil {
		t.Fatalf("ParserFor(%s): %v", path, err)
	}
	parsed, err := p.Parse(content)
	if err != nil {
		t.Fatalf("Parse(%s): %v", path, err)
	}

	ctx := analyzer.Context{File: parsed, Dir: filepath.Dir(path)}

	ids := map[string]bool{}
	for _, a := range reg.Analyzers {
		findings, err := a.Analyze(ctx)
		if err != nil {
			t.Fatalf("%s.Analyze(%s): %v", a.Name(), path, err)
		}
		for _, f := range findings {
			if f.RuleID != "" {
				ids[f.RuleID] = true
			}
		}
	}
	return ids
}

func TestFixturesEndToEnd(t *testing.T) {
	tests := []struct {
		file    string
		wantHas []string
		wantNot []string
	}{
		{
			file:    "../../testdata/dockerfiles/insecure.Dockerfile",
			wantHas: []string{"S001", "S002", "S003", "S005", "S006", "S019"},
		},
		{
			file:    "../../testdata/dockerfiles/inefficient.Dockerfile",
			wantHas: []string{"P001", "P002", "P003", "P008", "P009", "P011", "S011", "S019"},
		},
		{
			file:    "../../testdata/dockerfiles/multistage.Dockerfile",
			wantHas: []string{"S005"}, // distroless final stage has no explicit tag
			wantNot: []string{"S001", "P005", "P007", "P010"},
		},
		{
			file:    "../../testdata/dockerfiles/simple.Dockerfile",
			wantNot: []string{"S001", "S005", "S007"},
		},
		{
			file: "../../testdata/dockerfiles/advanced-vulns.Dockerfile",
			wantHas: []string{
				"S001", "S003", "S007", "S009", "S013", "S014", "S015", "S016", "S017", "S018",
				"P003", "P007", "P010",
			},
		},
		{
			file:    "../../testdata/dockerfiles/buildkit-features.Dockerfile",
			wantHas: []string{"S011", "P002", "P008"},
			wantNot: []string{"S005", "S018", "P007"},
		},
		{
			file:    "../../testdata/dockerfiles/cross-stage-leak.Dockerfile",
			wantHas: []string{"S009", "S024"},
		},
		{
			file:    "../../testdata/dockerfiles/missing-copy-source.Dockerfile",
			wantHas: []string{"P017"},
		},
		{
			file: "../../testdata/compose/docker-compose.clean.yml",
			wantNot: []string{
				"C001", "C002", "C003", "C004", "C005", "C006", "C007",
				"C008", "C009", "C013", "C014", "C015", "C016", "C017",
			},
		},
		{
			file: "../../testdata/compose/docker-compose.insecure.yml",
			wantHas: []string{
				"C001", "C002", "C003", "C004", "C005", "C006",
				"C008", "C009", "C013", "C014", "C015", "C016", "C017",
			},
		},
		{
			file:    "../../testdata/compose/build-reference/docker-compose.yml",
			wantHas: []string{"C010", "C011", "C012"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.file, func(t *testing.T) {
			ids := ruleIDs(t, tt.file)
			for _, want := range tt.wantHas {
				if !ids[want] {
					t.Errorf("expected rule %s to fire; got %v", want, ids)
				}
			}
			for _, notWant := range tt.wantNot {
				if ids[notWant] {
					t.Errorf("did not expect rule %s to fire; got %v", notWant, ids)
				}
			}
		})
	}
}

func TestParserForUnknownFile(t *testing.T) {
	reg := New()
	if _, err := reg.ParserFor("Makefile", ""); err == nil {
		t.Error("expected an error for a file type with no registered parser")
	}
}

func TestParserForRecognizesComposeByFilename(t *testing.T) {
	reg := New()
	p, err := reg.ParserFor("docker-compose.yml", "")
	if err != nil {
		t.Fatalf("ParserFor: %v", err)
	}
	if fileType(p) != "compose" {
		t.Errorf("resolved parser type = %q, want compose", fileType(p))
	}
}

func TestParserForTypeOverride(t *testing.T) {
	reg := New()

	p, err := reg.ParserFor("weirdly-named-file.txt", "compose")
	if err != nil {
		t.Fatalf("ParserFor with --type override: %v", err)
	}
	if fileType(p) != "compose" {
		t.Errorf("resolved parser type = %q, want compose", fileType(p))
	}

	if _, err := reg.ParserFor("anything", "bogus"); err == nil {
		t.Error("expected an error for an unrecognized --type value")
	}
}
