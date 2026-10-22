package explain

import (
	"strings"
	"testing"

	"github.com/onatribar/dockscribe/pkg/analyzer"
	"github.com/onatribar/dockscribe/pkg/parser/dockerfile"
)

func messages(t *testing.T, src string) []string {
	t.Helper()
	parsed, err := dockerfile.New().Parse([]byte(src))
	if err != nil {
		t.Fatalf("parsing fixture: %v", err)
	}
	findings, err := New().Analyze(analyzer.Context{File: parsed})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	var out []string
	for _, f := range findings {
		if f.Category != analyzer.CategoryExplanation {
			t.Errorf("unexpected category %q on explanation finding", f.Category)
		}
		if f.Severity != analyzer.Info {
			t.Errorf("unexpected severity %v on explanation finding", f.Severity)
		}
		out = append(out, f.Message)
	}
	return out
}

func TestExplainCoversEveryInstruction(t *testing.T) {
	src := "FROM node:18-alpine AS builder\n" +
		"WORKDIR /app\n" +
		"COPY package.json ./\n" +
		"RUN npm ci\n" +
		"ADD https://example.com/x.tar.gz /opt/\n" +
		"ENV NODE_ENV=production\n" +
		"ARG VERSION=1.0\n" +
		"EXPOSE 3000\n" +
		"LABEL maintainer=me\n" +
		"VOLUME /data\n" +
		"HEALTHCHECK CMD true\n" +
		"SHELL [\"/bin/bash\", \"-c\"]\n" +
		"ONBUILD RUN echo hi\n" +
		"STOPSIGNAL SIGTERM\n" +
		"USER node\n" +
		"ENTRYPOINT [\"node\"]\n" +
		"CMD [\"server.js\"]\n"

	msgs := messages(t, src)
	if len(msgs) != 17 {
		t.Fatalf("expected 17 explanation findings (one per instruction), got %d:\n%s", len(msgs), strings.Join(msgs, "\n"))
	}
}

func TestExplainFromNamesStage(t *testing.T) {
	msgs := messages(t, "FROM node:18-alpine AS builder\nCMD [\"true\"]\n")
	if !strings.Contains(msgs[0], "builder") {
		t.Errorf("expected FROM explanation to mention the stage name, got %q", msgs[0])
	}
}

func TestExplainCopyMentionsFromStage(t *testing.T) {
	src := "FROM golang AS builder\nRUN true\n\nFROM alpine\nCOPY --from=builder /out/app /app\n"
	msgs := messages(t, src)
	last := msgs[len(msgs)-1]
	if !strings.Contains(last, "builder") {
		t.Errorf("expected COPY --from explanation to mention the source stage, got %q", last)
	}
}

func TestExplainEnvWithAndWithoutEquals(t *testing.T) {
	msgs := messages(t, "FROM alpine\nENV FOO=bar\nENV BAZ qux\n")
	if !strings.Contains(msgs[1], "FOO") || !strings.Contains(msgs[1], "bar") {
		t.Errorf("ENV FOO=bar explanation = %q", msgs[1])
	}
	if !strings.Contains(msgs[2], "BAZ") || !strings.Contains(msgs[2], "qux") {
		t.Errorf("ENV BAZ qux explanation = %q", msgs[2])
	}
}

func TestNonDockerfileInputIsIgnored(t *testing.T) {
	findings, err := New().Analyze(analyzer.Context{})
	if err != nil {
		t.Fatalf("Analyze(nil): %v", err)
	}
	if findings != nil {
		t.Errorf("expected no findings for a non-dockerfile ParsedFile, got %v", findings)
	}
}
