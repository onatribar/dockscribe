package compose

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/onatribar/dockscribe/pkg/analyzer"
	"github.com/onatribar/dockscribe/pkg/parser/compose"
)

func analyze(t *testing.T, src string, dir string) []analyzer.Finding {
	t.Helper()
	parsed, err := compose.New().Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	findings, err := New().Analyze(analyzer.Context{File: parsed, Dir: dir})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	return findings
}

func hasRule(findings []analyzer.Finding, ruleID string) bool {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

func TestCheckPrivileged(t *testing.T) {
	f := analyze(t, "services:\n  app:\n    image: x\n    privileged: true\n", "")
	if !hasRule(f, "C001") {
		t.Errorf("expected C001, got %+v", f)
	}
}

func TestCheckPrivilegedNotSet(t *testing.T) {
	f := analyze(t, "services:\n  app:\n    image: x\n", "")
	if hasRule(f, "C001") {
		t.Error("did not expect C001 when privileged isn't set")
	}
}

func TestCheckDockerSocketMount(t *testing.T) {
	f := analyze(t, "services:\n  app:\n    image: x\n    volumes:\n      - /var/run/docker.sock:/var/run/docker.sock\n", "")
	if !hasRule(f, "C002") {
		t.Errorf("expected C002, got %+v", f)
	}
}

func TestCheckHostNetwork(t *testing.T) {
	f := analyze(t, "services:\n  app:\n    image: x\n    network_mode: host\n", "")
	if !hasRule(f, "C003") {
		t.Errorf("expected C003, got %+v", f)
	}
}

func TestCheckSensitiveMount(t *testing.T) {
	tests := []struct {
		name    string
		volume  string
		wantHit bool
	}{
		{"ssh dir", "/home/user/.ssh:/root/.ssh", true},
		{"aws creds", "~/.aws:/root/.aws:ro", true},
		{"host root", "/:/hostroot", true},
		{"etc", "/etc:/etc", true},
		{"named volume, benign", "data:/var/lib/data", false},
		{"project dir, benign", ".:/app", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			src := "services:\n  app:\n    image: x\n    volumes:\n      - \"" + tt.volume + "\"\n"
			f := analyze(t, src, "")
			if got := hasRule(f, "C004"); got != tt.wantHit {
				t.Errorf("C004 = %v, want %v (findings: %+v)", got, tt.wantHit, f)
			}
		})
	}
}

func TestCheckEnvironmentSecrets(t *testing.T) {
	t.Run("secret-looking name", func(t *testing.T) {
		f := analyze(t, "services:\n  app:\n    image: x\n    environment:\n      API_PASSWORD: hunter2placeholder\n", "")
		if !hasRule(f, "C005") {
			t.Errorf("expected C005, got %+v", f)
		}
	})
	t.Run("known-format value", func(t *testing.T) {
		f := analyze(t, "services:\n  app:\n    image: x\n    environment:\n      TOKEN: \"AKIAIOSFODNN7EXAMPLE\"\n", "")
		if !hasRule(f, "C006") {
			t.Errorf("expected C006, got %+v", f)
		}
	})
	t.Run("ordinary value", func(t *testing.T) {
		f := analyze(t, "services:\n  app:\n    image: x\n    environment:\n      NODE_ENV: production\n", "")
		if hasRule(f, "C005") || hasRule(f, "C006") || hasRule(f, "C007") {
			t.Errorf("did not expect a secret finding for an ordinary value, got %+v", f)
		}
	})
}

func TestCheckUnconfinedSecurityOpt(t *testing.T) {
	f := analyze(t, "services:\n  app:\n    image: x\n    security_opt:\n      - seccomp:unconfined\n", "")
	if !hasRule(f, "C013") {
		t.Errorf("expected C013, got %+v", f)
	}
}

func TestCheckDangerousCapabilities(t *testing.T) {
	f := analyze(t, "services:\n  app:\n    image: x\n    cap_add:\n      - SYS_ADMIN\n", "")
	if !hasRule(f, "C014") {
		t.Errorf("expected C014, got %+v", f)
	}
	f2 := analyze(t, "services:\n  app:\n    image: x\n    cap_add:\n      - NET_BIND_SERVICE\n", "")
	if hasRule(f2, "C014") {
		t.Errorf("did not expect C014 for a narrow capability, got %+v", f2)
	}
}

func TestCheckSensitivePort(t *testing.T) {
	f := analyze(t, "services:\n  app:\n    image: x\n    ports:\n      - \"2222:22\"\n", "")
	if !hasRule(f, "C015") {
		t.Errorf("expected C015, got %+v", f)
	}
	f2 := analyze(t, "services:\n  app:\n    image: x\n    ports:\n      - \"8080:80\"\n", "")
	if hasRule(f2, "C015") {
		t.Errorf("did not expect C015 for an ordinary port, got %+v", f2)
	}
}

func TestCheckNoResourceLimits(t *testing.T) {
	f := analyze(t, "services:\n  app:\n    image: x\n", "")
	if !hasRule(f, "C008") {
		t.Errorf("expected C008, got %+v", f)
	}
	f2 := analyze(t, "services:\n  app:\n    image: x\n    mem_limit: 256m\n", "")
	if hasRule(f2, "C008") {
		t.Errorf("did not expect C008 when a limit is set, got %+v", f2)
	}
}

func TestCheckNoRestartPolicy(t *testing.T) {
	f := analyze(t, "services:\n  app:\n    image: x\n", "")
	if !hasRule(f, "C009") {
		t.Errorf("expected C009, got %+v", f)
	}
	f2 := analyze(t, "services:\n  app:\n    image: x\n    restart: unless-stopped\n", "")
	if hasRule(f2, "C009") {
		t.Errorf("did not expect C009 when a restart policy is set, got %+v", f2)
	}
}

func TestCheckBuildDockerfileMissing(t *testing.T) {
	dir := t.TempDir()
	f := analyze(t, "services:\n  app:\n    build: .\n", dir)
	if !hasRule(f, "C010") {
		t.Errorf("expected C010, got %+v", f)
	}
}

func TestCheckBuildTargetMissingStage(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Dockerfile", "FROM golang:1.22 AS builder\nRUN true\n")
	f := analyze(t, "services:\n  app:\n    build:\n      context: .\n      target: nonexistent\n", dir)
	if !hasRule(f, "C011") {
		t.Errorf("expected C011, got %+v", f)
	}
}

func TestCheckBuildTargetValidStage(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Dockerfile", "FROM golang:1.22 AS builder\nRUN true\n")
	f := analyze(t, "services:\n  app:\n    build:\n      context: .\n      target: builder\n", dir)
	if hasRule(f, "C011") {
		t.Errorf("did not expect C011 for a valid target, got %+v", f)
	}
}

func TestCheckUserOverride(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Dockerfile", "FROM alpine\nUSER app\n")
	f := analyze(t, "services:\n  app:\n    build: .\n    user: root\n", dir)
	if !hasRule(f, "C012") {
		t.Errorf("expected C012, got %+v", f)
	}
}

func TestCheckUserOverrideNotSet(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Dockerfile", "FROM alpine\nUSER app\n")
	f := analyze(t, "services:\n  app:\n    build: .\n", dir)
	if hasRule(f, "C012") {
		t.Errorf("did not expect C012 when user: isn't set, got %+v", f)
	}
}

func TestCheckBuildReferenceSharedAcrossServices(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "Dockerfile", "FROM alpine\nUSER app\n")
	src := "services:\n" +
		"  web:\n    build: .\n    user: root\n" +
		"  worker:\n    build: .\n"
	f := analyze(t, src, dir)
	if !hasRule(f, "C012") {
		t.Errorf("expected C012 for the service overriding user, got %+v", f)
	}
	count := 0
	for _, finding := range f {
		if finding.RuleID == "C012" {
			count++
		}
	}
	if count != 1 {
		t.Errorf("expected exactly 1 C012 finding (only \"web\" overrides user), got %d: %+v", count, f)
	}
}

func TestCheckBuildReferenceSharedMissingDockerfileReportsPerService(t *testing.T) {
	dir := t.TempDir()
	src := "services:\n" +
		"  a:\n    build: .\n" +
		"  b:\n    build: .\n"
	f := analyze(t, src, dir)
	count := 0
	for _, finding := range f {
		if finding.RuleID == "C010" {
			count++
		}
	}
	if count != 2 {
		t.Errorf("expected a C010 finding for both services, got %d: %+v", count, f)
	}
}

func TestCheckImageReferenceMutableTag(t *testing.T) {
	f := analyze(t, "services:\n  db:\n    image: postgres:latest\n", "")
	if !hasRule(f, "C016") {
		t.Errorf("expected C016 for a mutable image tag, got %+v", f)
	}
	f2 := analyze(t, "services:\n  db:\n    image: postgres:16.4\n", "")
	if hasRule(f2, "C016") {
		t.Errorf("did not expect C016 for a pinned image tag, got %+v", f2)
	}
}

func TestCheckImageReferenceEOL(t *testing.T) {
	f := analyze(t, "services:\n  app:\n    image: node:14\n", "")
	if !hasRule(f, "C017") {
		t.Errorf("expected C017 for an end-of-life image, got %+v", f)
	}
}

func TestCheckImageReferenceSkippedWhenBuildIsSet(t *testing.T) {
	f := analyze(t, "services:\n  app:\n    build: .\n    image: myapp:latest\n", "")
	if hasRule(f, "C016") || hasRule(f, "C017") {
		t.Errorf("did not expect C016/C017 when build: is also set, got %+v", f)
	}
}

func TestCheckBuildReferenceRemoteContextSkipped(t *testing.T) {
	f := analyze(t, "services:\n  app:\n    build: https://github.com/example/repo.git\n", t.TempDir())
	if hasRule(f, "C010") {
		t.Errorf("did not expect C010 for a remote build context, got %+v", f)
	}
}

func TestFindingOrderIsDeterministic(t *testing.T) {
	src := "services:\n  app:\n    image: x\n    environment:\n" +
		"      DB_PASSWORD: hunter2placeholder\n" +
		"      AWS_KEY: \"AKIAIOSFODNN7EXAMPLE\"\n" +
		"      API_TOKEN: another-placeholder\n"

	first := analyze(t, src, "")
	for i := 0; i < 20; i++ {
		got := analyze(t, src, "")
		if len(got) != len(first) {
			t.Fatalf("run %d: got %d findings, want %d", i, len(got), len(first))
		}
		for j := range got {
			if got[j].RuleID != first[j].RuleID || got[j].Message != first[j].Message {
				t.Fatalf("run %d: finding order differs at index %d:\n  first: %s %s\n  got:   %s %s",
					i, j, first[j].RuleID, first[j].Message, got[j].RuleID, got[j].Message)
			}
		}
	}
}

func TestAnalyzeEmptyComposeFile(t *testing.T) {
	f := analyze(t, "", "")
	if len(f) != 0 {
		t.Errorf("expected no findings for an empty compose file, got %+v", f)
	}
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
}
