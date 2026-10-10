package performance

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/onatribar/dockscribe/pkg/analyzer"
	"github.com/onatribar/dockscribe/pkg/parser/dockerfile"
)

func analyze(t *testing.T, src string, dir string) []analyzer.Finding {
	t.Helper()
	p := dockerfile.New()
	parsed, err := p.Parse([]byte(src))
	if err != nil {
		t.Fatalf("parsing fixture: %v", err)
	}
	findings, err := New().Analyze(analyzer.Context{File: parsed, Dir: dir})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	return findings
}

func ruleIDs(findings []analyzer.Finding) map[string]bool {
	out := map[string]bool{}
	for _, f := range findings {
		out[f.RuleID] = true
	}
	return out
}

func TestMultiStage(t *testing.T) {
	if !ruleIDs(analyze(t, "FROM golang:1.22-alpine\nRUN go build -o /out/app .\n", ""))["P005"] {
		t.Error("expected P005 for a single-stage build")
	}
	src := "FROM golang:1.22-alpine AS builder\nRUN go build -o /out/app .\n\nFROM alpine\nCOPY --from=builder /out/app /app\n"
	if ruleIDs(analyze(t, src, ""))["P005"] {
		t.Error("did not expect P005 for a multi-stage build")
	}
}

func TestFinalBaseImage(t *testing.T) {
	tests := []struct {
		name    string
		from    string
		wantHit bool
	}{
		{"heavy ubuntu", "FROM ubuntu:22.04", true},
		{"heavy node", "FROM node:18", true},
		{"node alpine variant", "FROM node:18-alpine", false},
		{"node slim variant", "FROM node:18-slim", false},
		{"unrelated image", "FROM gcr.io/distroless/static-debian12", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ruleIDs(analyze(t, tt.from+"\nRUN true\n", ""))["P007"]
			if got != tt.wantHit {
				t.Errorf("P007 = %v, want %v", got, tt.wantHit)
			}
		})
	}
	t.Run("heavy intermediate build stage is not flagged", func(t *testing.T) {
		src := "FROM golang:1.22 AS builder\nRUN go build .\n\nFROM gcr.io/distroless/static-debian12\nCOPY --from=builder /out/app /app\n"
		if ruleIDs(analyze(t, src, ""))["P007"] {
			t.Error("expected P007 to only evaluate the final stage's base image")
		}
	})
}

func TestConsecutiveRun(t *testing.T) {
	if !ruleIDs(analyze(t, "FROM alpine\nRUN echo one\nRUN echo two\nRUN echo three\n", ""))["P003"] {
		t.Error("expected P003 for 3 consecutive RUN instructions")
	}
	if ruleIDs(analyze(t, "FROM alpine\nRUN echo one\nCOPY . /app\nRUN echo two\n", ""))["P003"] {
		t.Error("did not expect P003 when RUNs are not consecutive")
	}
}

func TestEarlyBroadCopy(t *testing.T) {
	if !ruleIDs(analyze(t, "FROM node:18-alpine\nCOPY . .\nRUN npm ci\n", ""))["P001"] {
		t.Error("expected P001 when full context is copied before npm ci")
	}
	src := "FROM node:18-alpine\nCOPY package.json package-lock.json ./\nRUN npm ci\nCOPY . .\n"
	if ruleIDs(analyze(t, src, ""))["P001"] {
		t.Error("did not expect P001 when manifests are copied before install")
	}
	t.Run("go mod download recognized", func(t *testing.T) {
		src := "FROM golang:1.22-alpine\nCOPY . .\nRUN go mod download\n"
		if !ruleIDs(analyze(t, src, ""))["P001"] {
			t.Error("expected P001 for go mod download after a broad copy")
		}
	})
}

func TestPackageCacheCleanup(t *testing.T) {
	if !ruleIDs(analyze(t, "FROM ubuntu\nRUN apt-get update && apt-get install -y curl\n", ""))["P002"] {
		t.Error("expected P002 when the apt cache isn't purged")
	}
	src := "FROM ubuntu\nRUN apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*\n"
	if ruleIDs(analyze(t, src, ""))["P002"] {
		t.Error("did not expect P002 when the apt cache is purged in the same layer")
	}
	if ruleIDs(analyze(t, "FROM alpine\nRUN apk add --no-cache curl\n", ""))["P002"] {
		t.Error("did not expect P002 when apk add uses --no-cache")
	}
	t.Run("pip", func(t *testing.T) {
		if !ruleIDs(analyze(t, "FROM python:3.12-slim\nRUN pip install flask\n", ""))["P002"] {
			t.Error("expected P002 when pip install has no --no-cache-dir")
		}
		if ruleIDs(analyze(t, "FROM python:3.12-slim\nRUN pip install --no-cache-dir flask\n", ""))["P002"] {
			t.Error("did not expect P002 when pip install uses --no-cache-dir")
		}
	})
}

func TestAddVsCopy(t *testing.T) {
	if !ruleIDs(analyze(t, "FROM alpine\nADD ./assets /app/assets\n", ""))["P004"] {
		t.Error("expected P004 for ADD of a plain local directory")
	}
	if ruleIDs(analyze(t, "FROM alpine\nADD ./bundle.tar.gz /opt/\n", ""))["P004"] {
		t.Error("did not expect P004 for ADD of a local archive")
	}
	if ruleIDs(analyze(t, "FROM alpine\nADD https://example.com/x.sh /tmp/x.sh\n", ""))["P004"] {
		t.Error("did not expect P004 for ADD of a remote URL")
	}
}

func TestHeavyDirCopy(t *testing.T) {
	if !ruleIDs(analyze(t, "FROM node:18-alpine\nCOPY node_modules ./node_modules\n", ""))["P006"] {
		t.Error("expected P006 for copying node_modules from the build context")
	}
	if ruleIDs(analyze(t, "FROM node:18-alpine\nCOPY package.json ./\n", ""))["P006"] {
		t.Error("did not expect P006 for an ordinary manifest copy")
	}
}

func TestNoInstallRecommends(t *testing.T) {
	if !ruleIDs(analyze(t, "FROM ubuntu\nRUN apt-get install -y curl\n", ""))["P008"] {
		t.Error("expected P008 without --no-install-recommends")
	}
	if ruleIDs(analyze(t, "FROM ubuntu\nRUN apt-get install -y --no-install-recommends curl\n", ""))["P008"] {
		t.Error("did not expect P008 when --no-install-recommends is present")
	}
}

func TestAptUpdateAlone(t *testing.T) {
	if !ruleIDs(analyze(t, "FROM ubuntu\nRUN apt-get update\nRUN apt-get install -y curl\n", ""))["P009"] {
		t.Error("expected P009 when apt-get update is in its own RUN")
	}
	if ruleIDs(analyze(t, "FROM ubuntu\nRUN apt-get update && apt-get install -y curl\n", ""))["P009"] {
		t.Error("did not expect P009 when update and install share a layer")
	}
}

func TestDeadStage(t *testing.T) {
	src := "FROM golang:1.22 AS builder\nRUN go build .\n\nFROM alpine AS unused\nRUN echo hi\n\nFROM alpine\nCOPY --from=builder /out/app /app\n"
	findings := analyze(t, src, "")
	count := 0
	for _, f := range findings {
		if f.RuleID == "P010" {
			count++
		}
	}
	if count != 1 {
		t.Fatalf("expected exactly 1 P010 finding (the unused stage), got %d: %+v", count, findings)
	}

	t.Run("stage referenced by numeric index", func(t *testing.T) {
		src := "FROM golang:1.22 AS builder\nRUN go build .\n\nFROM alpine\nCOPY --from=0 /out/app /app\n"
		if ruleIDs(analyze(t, src, ""))["P010"] {
			t.Error("did not expect P010 when the stage is referenced by numeric index")
		}
	})

	t.Run("single stage never flagged", func(t *testing.T) {
		if ruleIDs(analyze(t, "FROM alpine\nRUN true\n", ""))["P010"] {
			t.Error("did not expect P010 for a single-stage build")
		}
	})
}

func TestDockerignoreMissing(t *testing.T) {
	dir := t.TempDir()
	if !ruleIDs(analyze(t, "FROM alpine\nCOPY . .\n", dir))["P011"] {
		t.Error("expected P011 for a broad COPY with no .dockerignore")
	}
}

func TestDockerignoreExcludesBloat(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".dockerignore"), []byte("node_modules\n.git\n__pycache__\n.venv\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if ruleIDs(analyze(t, "FROM alpine\nCOPY . .\n", dir))["P011"] {
		t.Error("did not expect P011 when .dockerignore covers all the checked bloat paths")
	}
}

func TestMissingCopySource(t *testing.T) {
	t.Run("missing source is flagged", func(t *testing.T) {
		dir := t.TempDir()
		if !ruleIDs(analyze(t, "FROM alpine\nCOPY package.json ./\n", dir))["P017"] {
			t.Error("expected P017 when the COPY source doesn't exist in the build context")
		}
	})

	t.Run("existing source is fine", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "package.json"), []byte("{}"), 0o644); err != nil {
			t.Fatal(err)
		}
		if ruleIDs(analyze(t, "FROM alpine\nCOPY package.json ./\n", dir))["P017"] {
			t.Error("did not expect P017 when the COPY source exists")
		}
	})

	t.Run("glob source matching a real file is fine", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte("print('hi')"), 0o644); err != nil {
			t.Fatal(err)
		}
		if ruleIDs(analyze(t, "FROM alpine\nCOPY *.py ./\n", dir))["P017"] {
			t.Error("did not expect P017 when a glob source matches a real file")
		}
	})

	t.Run("glob source matching nothing is flagged", func(t *testing.T) {
		dir := t.TempDir()
		if !ruleIDs(analyze(t, "FROM alpine\nCOPY *.py ./\n", dir))["P017"] {
			t.Error("expected P017 when a glob source matches nothing")
		}
	})

	t.Run("broad copy is never flagged", func(t *testing.T) {
		dir := t.TempDir()
		if ruleIDs(analyze(t, "FROM alpine\nCOPY . .\n", dir))["P017"] {
			t.Error("did not expect P017 for a broad COPY")
		}
	})

	t.Run("COPY --from is not a local filesystem source", func(t *testing.T) {
		dir := t.TempDir()
		src := "FROM golang AS builder\nRUN true\n\nFROM alpine\nCOPY --from=builder /out/app /app\n"
		if ruleIDs(analyze(t, src, dir))["P017"] {
			t.Error("did not expect P017 for a COPY --from another stage")
		}
	})

	t.Run("ADD with a URL is not a local filesystem source", func(t *testing.T) {
		dir := t.TempDir()
		if ruleIDs(analyze(t, "FROM alpine\nADD https://example.com/x.sh /tmp/x.sh\n", dir))["P017"] {
			t.Error("did not expect P017 for ADD with a URL source")
		}
	})

	t.Run("no context directory means no check", func(t *testing.T) {
		if ruleIDs(analyze(t, "FROM alpine\nCOPY package.json ./\n", ""))["P017"] {
			t.Error("did not expect P017 when ctx.Dir is unset")
		}
	})
}

func TestDanglingCopyFrom(t *testing.T) {
	t.Run("out of range index", func(t *testing.T) {
		src := "FROM golang AS builder\nRUN go build .\n\nFROM alpine\nCOPY --from=5 /out/app /app\n"
		if !ruleIDs(analyze(t, src, ""))["P012"] {
			t.Error("expected P012 for an out-of-range numeric --from index")
		}
	})
	t.Run("valid index", func(t *testing.T) {
		src := "FROM golang AS builder\nRUN go build .\n\nFROM alpine\nCOPY --from=0 /out/app /app\n"
		if ruleIDs(analyze(t, src, ""))["P012"] {
			t.Error("did not expect P012 for a valid numeric --from index")
		}
	})
	t.Run("named stage reference is not numeric, not our concern", func(t *testing.T) {
		src := "FROM golang AS builder\nRUN go build .\n\nFROM alpine\nCOPY --from=builder /out/app /app\n"
		if ruleIDs(analyze(t, src, ""))["P012"] {
			t.Error("did not expect P012 for a named stage reference")
		}
	})
	t.Run("external image reference is not numeric, not our concern", func(t *testing.T) {
		src := "FROM alpine\nCOPY --from=busybox /bin/busybox /bin/busybox\n"
		if ruleIDs(analyze(t, src, ""))["P012"] {
			t.Error("did not expect P012 for a non-numeric external image --from")
		}
	})
	t.Run("forward reference to a later stage is dangling", func(t *testing.T) {
		src := "FROM alpine AS a\nCOPY --from=1 /x /y\n\nFROM alpine AS b\nRUN true\n"
		if !ruleIDs(analyze(t, src, ""))["P012"] {
			t.Error("expected P012 when --from references a stage that hasn't been built yet")
		}
	})
}

func TestSelfReferentialCopyFrom(t *testing.T) {
	t.Run("self-reference by name", func(t *testing.T) {
		src := "FROM golang AS builder\nCOPY --from=builder /out/app /app\n"
		if !ruleIDs(analyze(t, src, ""))["P018"] {
			t.Error("expected P018 when COPY --from references its own stage's name")
		}
	})
	t.Run("reference to an earlier stage by name is fine", func(t *testing.T) {
		src := "FROM golang AS builder\nRUN go build .\n\nFROM alpine AS final\nCOPY --from=builder /out/app /app\n"
		if ruleIDs(analyze(t, src, ""))["P018"] {
			t.Error("did not expect P018 for a reference to a different, earlier stage")
		}
	})
	t.Run("unnamed stage cannot self-reference by name", func(t *testing.T) {
		src := "FROM golang\nCOPY --from=builder /out/app /app\n"
		if ruleIDs(analyze(t, src, ""))["P018"] {
			t.Error("did not expect P018 when the current stage has no name of its own")
		}
	})
}

func TestFullStageCopy(t *testing.T) {
	tests := []struct {
		name    string
		src     string
		wantHit bool
	}{
		{"dot source", "FROM golang AS builder\nRUN go build .\n\nFROM alpine\nCOPY --from=builder . /app\n", true},
		{"slash source", "FROM golang AS builder\nRUN go build .\n\nFROM alpine\nCOPY --from=builder / /app\n", true},
		{"star source", "FROM golang AS builder\nRUN go build .\n\nFROM alpine\nCOPY --from=builder * /app\n", true},
		{"specific artifact, not broad", "FROM golang AS builder\nRUN go build .\n\nFROM alpine\nCOPY --from=builder /out/app /app\n", false},
		{"no --from at all, unaffected", "FROM alpine\nCOPY . /app\n", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ruleIDs(analyze(t, tt.src, ""))["P019"]; got != tt.wantHit {
				t.Errorf("P019 = %v, want %v", got, tt.wantHit)
			}
		})
	}
}

func TestDuplicateStageNames(t *testing.T) {
	src := "FROM golang AS build\nRUN go build .\n\nFROM alpine AS build\nRUN true\n"
	if !ruleIDs(analyze(t, src, ""))["P013"] {
		t.Error("expected P013 for a duplicate stage name")
	}
	src = "FROM golang AS build\nRUN go build .\n\nFROM alpine AS final\nRUN true\n"
	if ruleIDs(analyze(t, src, ""))["P013"] {
		t.Error("did not expect P013 for distinct stage names")
	}
}

func TestRelativeWorkdir(t *testing.T) {
	if !ruleIDs(analyze(t, "FROM alpine\nWORKDIR app\n", ""))["P015"] {
		t.Error("expected P015 for a relative WORKDIR")
	}
	if ruleIDs(analyze(t, "FROM alpine\nWORKDIR /app\n", ""))["P015"] {
		t.Error("did not expect P015 for an absolute WORKDIR")
	}
	if ruleIDs(analyze(t, "FROM alpine\nWORKDIR $APP_HOME\n", ""))["P015"] {
		t.Error("did not expect P015 for a variable-reference WORKDIR")
	}
}

func TestHardcodedPlatform(t *testing.T) {
	if !ruleIDs(analyze(t, "FROM --platform=linux/amd64 alpine\n", ""))["P016"] {
		t.Error("expected P016 for a hardcoded --platform")
	}
	if ruleIDs(analyze(t, "FROM --platform=$BUILDPLATFORM alpine\n", ""))["P016"] {
		t.Error("did not expect P016 when --platform is driven by a build arg")
	}
	if ruleIDs(analyze(t, "FROM alpine\n", ""))["P016"] {
		t.Error("did not expect P016 when there is no --platform flag at all")
	}
}

func TestMissingPipefail(t *testing.T) {
	if !ruleIDs(analyze(t, "FROM alpine\nRUN curl -fsSL https://x/i.sh | bash\n", ""))["P014"] {
		t.Error("expected P014 for a piped RUN with no pipefail set")
	}
	t.Run("pipefail set via SHELL", func(t *testing.T) {
		src := "FROM alpine\nSHELL [\"/bin/bash\", \"-o\", \"pipefail\", \"-c\"]\nRUN curl -fsSL https://x/i.sh | bash\n"
		if ruleIDs(analyze(t, src, ""))["P014"] {
			t.Error("did not expect P014 once SHELL sets pipefail")
		}
	})
	t.Run("no pipe means no finding", func(t *testing.T) {
		if ruleIDs(analyze(t, "FROM alpine\nRUN echo hi\n", ""))["P014"] {
			t.Error("did not expect P014 for a RUN with no pipe")
		}
	})
}

func TestNonDockerfileInputIsIgnored(t *testing.T) {
	findings, err := New().Analyze(analyzer.Context{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if findings != nil {
		t.Errorf("expected no findings for a non-dockerfile ParsedFile, got %v", findings)
	}
}
