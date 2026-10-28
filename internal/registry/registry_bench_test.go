package registry

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/onatribar/dockscribe/pkg/analyzer"
)

var benchSink int

func benchmarkFile(b *testing.B, path string) {
	b.Helper()
	content, err := os.ReadFile(path)
	if err != nil {
		b.Fatalf("reading %s: %v", path, err)
	}
	reg := New()
	p, err := reg.ParserFor(path, "")
	if err != nil {
		b.Fatalf("ParserFor(%s): %v", path, err)
	}
	dir := filepath.Dir(path)

	b.ReportAllocs()
	b.ResetTimer()
	sink := 0
	for i := 0; i < b.N; i++ {
		parsed, err := p.Parse(content)
		if err != nil {
			b.Fatalf("Parse(%s): %v", path, err)
		}
		ctx := analyzer.Context{File: parsed, Dir: dir}
		for _, a := range reg.Analyzers {
			findings, err := a.Analyze(ctx)
			if err != nil {
				b.Fatalf("%s.Analyze(%s): %v", a.Name(), path, err)
			}
			sink += len(findings)
		}
	}
	benchSink = sink
}

// best-case-ish
func BenchmarkAnalyzeSimpleDockerfile(b *testing.B) {
	benchmarkFile(b, "../../testdata/dockerfiles/simple.Dockerfile")
}

// worst-case-ish
func BenchmarkAnalyzeAdvancedVulnsDockerfile(b *testing.B) {
	benchmarkFile(b, "../../testdata/dockerfiles/advanced-vulns.Dockerfile")
}

func BenchmarkAnalyzeComposeInsecure(b *testing.B) {
	benchmarkFile(b, "../../testdata/compose/docker-compose.insecure.yml")
}
