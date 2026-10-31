package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/onatribar/dockscribe/internal/registry"
	"github.com/onatribar/dockscribe/internal/suppress"
	"github.com/onatribar/dockscribe/pkg/analyzer"
	"github.com/onatribar/dockscribe/pkg/parser/dockerfile"
)

func writeTempDockerfile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "Dockerfile")
	if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestApplyFixesToFile(t *testing.T) {
	src := "FROM ubuntu:22.04\n" +
		"RUN apt-get update && apt-get install -y curl\n" +
		"ADD ./assets /app/assets\n" +
		"USER nobody\n" +
		"CMD [\"/app/run.sh\"]\n"
	path := writeTempDockerfile(t, src)
	// P004's ADD source needs to exist so P017 doesn't interfere with this test's focus.
	if err := os.Mkdir(filepath.Join(filepath.Dir(path), "assets"), 0o755); err != nil {
		t.Fatal(err)
	}

	p := dockerfile.New()
	content, _ := os.ReadFile(path)
	parsed, err := p.Parse(content)
	if err != nil {
		t.Fatal(err)
	}
	df := parsed.(*dockerfile.File)
	ctx := analyzer.Context{File: parsed, Dir: filepath.Dir(path)}

	var out bytes.Buffer
	reg := registry.New()
	fixed, err := applyFixesToFile(reg, path, content, df, ctx, suppress.Suppressions{}, &out)
	if err != nil {
		t.Fatalf("applyFixesToFile: %v", err)
	}

	want := "FROM ubuntu:22.04\n" +
		"RUN apt-get update && apt-get install --no-install-recommends -y curl && rm -rf /var/lib/apt/lists/*\n" +
		"COPY ./assets /app/assets\n" +
		"USER nobody\n" +
		"CMD [\"/app/run.sh\"]\n"
	if string(fixed) != want {
		t.Errorf("fixed content =\n%s\nwant\n%s", fixed, want)
	}

	onDisk, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(onDisk) != want {
		t.Errorf("file on disk =\n%s\nwant\n%s", onDisk, want)
	}

	if !bytes.Contains(out.Bytes(), []byte("P002")) || !bytes.Contains(out.Bytes(), []byte("P004")) || !bytes.Contains(out.Bytes(), []byte("P008")) {
		t.Errorf("expected the fix summary to mention P002, P004, and P008, got:\n%s", out.String())
	}
}

func TestApplyFixesToFileNoOp(t *testing.T) {
	src := "FROM alpine\nUSER app\nCMD [\"/app\"]\n"
	path := writeTempDockerfile(t, src)

	p := dockerfile.New()
	content, _ := os.ReadFile(path)
	parsed, _ := p.Parse(content)
	df := parsed.(*dockerfile.File)
	ctx := analyzer.Context{File: parsed, Dir: filepath.Dir(path)}

	var out bytes.Buffer
	reg := registry.New()
	fixed, err := applyFixesToFile(reg, path, content, df, ctx, suppress.Suppressions{}, &out)
	if err != nil {
		t.Fatalf("applyFixesToFile: %v", err)
	}
	if !bytes.Equal(fixed, content) {
		t.Errorf("expected content unchanged when nothing is fixable, got:\n%s", fixed)
	}
	if out.Len() != 0 {
		t.Errorf("expected no fix summary output when nothing changed, got:\n%s", out.String())
	}
}

func TestApplyFixesToFileSkipsMultiLineInstructions(t *testing.T) {
	// A backslash-continued RUN spans multiple physical lines - fixing it
	// would mean rewriting a multi-line span, which applyFixesToFile
	// deliberately never attempts. The finding should remain (uncorrected)
	// rather than the file being silently left half-fixed or corrupted.
	src := "FROM ubuntu\n" +
		"RUN apt-get update && \\\n" +
		"    apt-get install -y curl\n" +
		"USER app\n"
	path := writeTempDockerfile(t, src)

	p := dockerfile.New()
	content, _ := os.ReadFile(path)
	parsed, _ := p.Parse(content)
	df := parsed.(*dockerfile.File)
	ctx := analyzer.Context{File: parsed, Dir: filepath.Dir(path)}

	var out bytes.Buffer
	reg := registry.New()
	fixed, err := applyFixesToFile(reg, path, content, df, ctx, suppress.Suppressions{}, &out)
	if err != nil {
		t.Fatalf("applyFixesToFile: %v", err)
	}
	if !bytes.Equal(fixed, content) {
		t.Errorf("expected content unchanged for a multi-line RUN, got:\n%s", fixed)
	}
}

func TestApplyFixesToFileRespectsSuppression(t *testing.T) {
	// This RUN independently trips both P002 (no cache cleanup) and P008 (no
	// --no-install-recommends) - the wildcard suppresses both, proving the
	// whole line is left alone rather than just whichever rule happened to
	// be named.
	src := "FROM ubuntu:22.04\n" +
		"# dockscribe-ignore=*\n" +
		"RUN apt-get install -y curl\n" +
		"USER app\n"
	path := writeTempDockerfile(t, src)

	p := dockerfile.New()
	content, _ := os.ReadFile(path)
	parsed, _ := p.Parse(content)
	df := parsed.(*dockerfile.File)
	ctx := analyzer.Context{File: parsed, Dir: filepath.Dir(path)}
	suppressed := suppress.Parse(parsed.RawLines())

	var out bytes.Buffer
	reg := registry.New()
	fixed, err := applyFixesToFile(reg, path, content, df, ctx, suppressed, &out)
	if err != nil {
		t.Fatalf("applyFixesToFile: %v", err)
	}
	if !bytes.Equal(fixed, content) {
		t.Errorf("expected the suppressed P008 finding to be left unfixed, got:\n%s", fixed)
	}
	if out.Len() != 0 {
		t.Errorf("expected no fix summary output for a fully-suppressed file, got:\n%s", out.String())
	}
}

func TestApplyFixesToFileSuppressionIsPerRule(t *testing.T) {
	// Suppressing P008 by name must not also silence P002 - a different,
	// independently-triggered rule on the same line that was never named.
	src := "FROM ubuntu:22.04\n" +
		"# dockscribe-ignore=P008\n" +
		"RUN apt-get install -y curl\n" +
		"USER app\n"
	path := writeTempDockerfile(t, src)

	p := dockerfile.New()
	content, _ := os.ReadFile(path)
	parsed, _ := p.Parse(content)
	df := parsed.(*dockerfile.File)
	ctx := analyzer.Context{File: parsed, Dir: filepath.Dir(path)}
	suppressed := suppress.Parse(parsed.RawLines())

	var out bytes.Buffer
	reg := registry.New()
	fixed, err := applyFixesToFile(reg, path, content, df, ctx, suppressed, &out)
	if err != nil {
		t.Fatalf("applyFixesToFile: %v", err)
	}
	if bytes.Contains(fixed, []byte("--no-install-recommends")) {
		t.Errorf("expected the suppressed P008 fix not to be applied, got:\n%s", fixed)
	}
	if !bytes.Contains(fixed, []byte("rm -rf /var/lib/apt/lists/*")) {
		t.Errorf("expected the unsuppressed P002 fix to still be applied, got:\n%s", fixed)
	}
}

func TestExecuteWithFixFlag(t *testing.T) {
	src := "FROM ubuntu:22.04\nRUN apt-get install -y curl\nUSER app\n"
	path := writeTempDockerfile(t, src)

	resetFlags(t)
	rootCmd.SetArgs([]string{"--no-explain", "--fix", "--fail-on", "never", path})
	rootCmd.SetOut(&bytes.Buffer{})
	var stderr bytes.Buffer
	rootCmd.SetErr(&stderr)

	if got := Execute(); got != 0 {
		t.Errorf("Execute() = %d, want 0", got)
	}

	fixed, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(fixed, []byte("--no-install-recommends")) {
		t.Errorf("expected the file to be fixed in place, got:\n%s", fixed)
	}
	if !bytes.Contains(stderr.Bytes(), []byte("Fixed")) {
		t.Errorf("expected a fix summary on stderr, got:\n%s", stderr.String())
	}
}
