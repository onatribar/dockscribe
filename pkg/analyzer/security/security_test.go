package security

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/onatribar/dockscribe/pkg/analyzer"
	"github.com/onatribar/dockscribe/pkg/parser/dockerfile"
)

// analyze parses src as a Dockerfile and runs the security analyzer over it
// dir, if non-empty, becomes ctx.Dir (for .dockerignore-aware checks)
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

func TestRootUser(t *testing.T) {
	t.Run("no USER at all", func(t *testing.T) {
		if !ruleIDs(analyze(t, "FROM alpine\nCMD [\"/bin/true\"]\n", ""))["S001"] {
			t.Error("expected S001 for missing USER")
		}
	})
	t.Run("USER root explicit", func(t *testing.T) {
		if !ruleIDs(analyze(t, "FROM alpine\nUSER root\nCMD [\"/bin/true\"]\n", ""))["S001"] {
			t.Error("expected S001 for USER root")
		}
	})
	t.Run("non-root USER", func(t *testing.T) {
		if ruleIDs(analyze(t, "FROM alpine\nUSER app\nCMD [\"/bin/true\"]\n", ""))["S001"] {
			t.Error("did not expect S001 when a non-root USER is set")
		}
	})
	t.Run("only checks final stage", func(t *testing.T) {
		src := "FROM golang AS builder\nUSER root\nRUN go build .\n\nFROM alpine\nUSER app\nCMD [\"/app\"]\n"
		if ruleIDs(analyze(t, src, ""))["S001"] {
			t.Error("root USER in a non-final stage should not trigger S001")
		}
	})
}

func TestHealthcheck(t *testing.T) {
	if !ruleIDs(analyze(t, "FROM alpine\nUSER app\nCMD [\"/bin/true\"]\n", ""))["S007"] {
		t.Error("expected S007 when no HEALTHCHECK is present")
	}
	if ruleIDs(analyze(t, "FROM alpine\nHEALTHCHECK CMD true\nUSER app\nCMD [\"/bin/true\"]\n", ""))["S007"] {
		t.Error("did not expect S007 when HEALTHCHECK is present")
	}
}

func TestMutableBaseImage(t *testing.T) {
	tests := []struct {
		name    string
		from    string
		wantHit bool
	}{
		{"explicit latest", "FROM ubuntu:latest", true},
		{"no tag", "FROM ubuntu", true},
		{"branch-like tag", "FROM myimage:main", true},
		{"pinned version", "FROM node:18.20.4-alpine3.19", false},
		{"digest pinned", "FROM node@sha256:abcdef0123abcdef0123abcdef0123abcdef0123abcdef0123abcdef0123ab", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ruleIDs(analyze(t, tt.from+"\nUSER app\n", ""))["S005"]
			if got != tt.wantHit {
				t.Errorf("S005 = %v, want %v", got, tt.wantHit)
			}
		})
	}
	t.Run("stage self-reference is not a mutable image", func(t *testing.T) {
		src := "FROM golang:1.22 AS builder\nRUN go build .\n\nFROM builder\nUSER app\n"
		if ruleIDs(analyze(t, src, ""))["S005"] {
			t.Error("expected no S005 for stage self-reference")
		}
	})
}

func TestEOLBaseImage(t *testing.T) {
	tests := []struct {
		name    string
		from    string
		wantHit bool
	}{
		{"python 2", "FROM python:2.7", true},
		{"node 14", "FROM node:14", true},
		{"ubuntu 18.04", "FROM ubuntu:18.04", true},
		{"centos any tag", "FROM centos:7", true},
		{"current python", "FROM python:3.12-slim", false},
		{"current node", "FROM node:22-alpine", false},
		{"unrelated image", "FROM gcr.io/distroless/static-debian12", false},
		{"boundary: 3.1 must not match 3.10+", "FROM python:3.10-slim", false},
		{"boundary: 3.2 must not match 3.20+", "FROM alpine:3.22", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ruleIDs(analyze(t, tt.from+"\nUSER app\n", ""))["S018"]
			if got != tt.wantHit {
				t.Errorf("S018 = %v, want %v", got, tt.wantHit)
			}
		})
	}
}

func TestAddURL(t *testing.T) {
	if !ruleIDs(analyze(t, "FROM alpine\nADD https://example.com/x.sh /tmp/x.sh\nUSER app\n", ""))["S002"] {
		t.Error("expected S002 for ADD with a remote URL")
	}
	if ruleIDs(analyze(t, "FROM alpine\nADD ./local.tar.gz /opt/\nUSER app\n", ""))["S002"] {
		t.Error("did not expect S002 for a local ADD source")
	}
}

func TestSecretNames(t *testing.T) {
	tests := []struct {
		instr   string
		wantHit bool
	}{
		{"ARG GITHUB_TOKEN", true},
		{"ARG API_SECRET=x", true},
		{"ENV DB_PASSWORD=hunter2", true},
		{"ARG BUILD_VERSION=1.0", false},
		{"ENV NODE_ENV=production", false},
	}
	for _, tt := range tests {
		t.Run(tt.instr, func(t *testing.T) {
			got := ruleIDs(analyze(t, "FROM alpine\n"+tt.instr+"\nUSER app\n", ""))["S003"]
			if got != tt.wantHit {
				t.Errorf("S003 for %q = %v, want %v", tt.instr, got, tt.wantHit)
			}
		})
	}
	t.Run("multiple ENV pairs on one line", func(t *testing.T) {
		findings := analyze(t, "FROM alpine\nENV FOO=bar API_TOKEN=abc\nUSER app\n", "")
		count := 0
		for _, f := range findings {
			if f.RuleID == "S003" {
				count++
			}
		}
		if count != 1 {
			t.Errorf("expected exactly 1 S003 finding, got %d", count)
		}
	})
}

func TestSecretValueKnownFormat(t *testing.T) {
	if !ruleIDs(analyze(t, "FROM alpine\nENV KEY=AKIAIOSFODNN7EXAMPLE\nUSER app\n", ""))["S013"] {
		t.Error("expected S013 for a value matching a known credential format")
	}
}

func TestSecretValueEntropy(t *testing.T) {
	findings := analyze(t, "FROM alpine\nENV SESSION_HASH=aZ9kQ7mX2vB8nC4wE6rT1yU3iO5pL0sD\nUSER app\n", "")
	ids := ruleIDs(findings)
	if !ids["S014"] {
		t.Error("expected S014 for a high-entropy value with an innocuous name")
	}
	if ids["S003"] {
		t.Error("did not expect S003 - the name isn't secret-like")
	}
}

func TestArgPromotedToEnv(t *testing.T) {
	src := "FROM alpine\nARG BUILD_SECRET\nENV BUILD_SECRET=$BUILD_SECRET\nUSER app\n"
	if !ruleIDs(analyze(t, src, ""))["S015"] {
		t.Error("expected S015 when a secret-like ARG is promoted into ENV")
	}

	t.Run("non-secret ARG promotion is fine", func(t *testing.T) {
		src := "FROM alpine\nARG VERSION=1.0\nENV VERSION=$VERSION\nUSER app\n"
		if ruleIDs(analyze(t, src, ""))["S015"] {
			t.Error("did not expect S015 for a non-secret-like ARG")
		}
	})
}

func TestArgUsedInRun(t *testing.T) {
	src := "FROM alpine\nARG DEPLOY_TOKEN\nRUN curl -H \"Authorization: Bearer $DEPLOY_TOKEN\" https://example.com\nUSER app\n"
	if !ruleIDs(analyze(t, src, ""))["S016"] {
		t.Error("expected S016 when a secret-like ARG is interpolated into RUN")
	}

	t.Run("non-secret ARG usage is fine", func(t *testing.T) {
		src := "FROM alpine\nARG VERSION\nRUN echo $VERSION\nUSER app\n"
		if ruleIDs(analyze(t, src, ""))["S016"] {
			t.Error("did not expect S016 for a non-secret-like ARG")
		}
	})
}

func TestArgScopeDoesNotCrossStages(t *testing.T) {
	// a secret-looking ARG declared in one stage isn't in scope in a later stage unless re/declared there
	// docker itself requires an ARG redeclaration inside each stage that uses it
	// a name that only reappears in a later stage's RUN shouldn't be treated as the same tainted var.
	t.Run("not redeclared in the later stage: no false positive", func(t *testing.T) {
		src := "FROM alpine AS builder\n" +
			"ARG API_SECRET_TOKEN=placeholder\n" +
			"RUN echo build > /out\n\n" +
			"FROM alpine\n" +
			"RUN echo \"not in scope here: $API_SECRET_TOKEN\"\n" +
			"USER app\n"
		if ruleIDs(analyze(t, src, ""))["S016"] {
			t.Error("did not expect S016: the ARG from stage 0 isn't in scope in stage 1")
		}
	})

	t.Run("redeclared bare in the later stage: still flagged", func(t *testing.T) {
		src := "ARG API_SECRET_TOKEN\n" +
			"FROM alpine\n" +
			"ARG API_SECRET_TOKEN\n" +
			"RUN echo $API_SECRET_TOKEN\n" +
			"USER app\n"
		if !ruleIDs(analyze(t, src, ""))["S016"] {
			t.Error("expected S016: the global ARG was correctly redeclared in this stage")
		}
	})
}

func TestChownMissingForNonRootUser(t *testing.T) {
	if !ruleIDs(analyze(t, "FROM alpine\nUSER app\nCOPY . /app\n", ""))["S004"] {
		t.Error("expected S004 when COPY has no --chown while USER is non-root")
	}
	if ruleIDs(analyze(t, "FROM alpine\nUSER app\nCOPY --chown=app:app . /app\n", ""))["S004"] {
		t.Error("did not expect S004 when --chown is present")
	}
	if ruleIDs(analyze(t, "FROM alpine\nCOPY . /app\nUSER app\n", ""))["S004"] {
		t.Error("did not expect S004 when COPY happens while still root")
	}
}

func TestCurlPipeShell(t *testing.T) {
	if !ruleIDs(analyze(t, "FROM alpine\nRUN curl -fsSL https://example.com/i.sh | bash\nUSER app\n", ""))["S006"] {
		t.Error("expected S006 for curl | bash")
	}
	if ruleIDs(analyze(t, "FROM alpine\nRUN curl -fsSL https://example.com/i.sh -o i.sh && bash i.sh\nUSER app\n", ""))["S006"] {
		t.Error("did not expect S006 when curl output is saved before executing")
	}
	t.Run("chained pipeline still detected", func(t *testing.T) {
		src := "FROM alpine\nRUN curl -fsSL https://x/i.sh | tee i.sh | bash\nUSER app\n"
		if !ruleIDs(analyze(t, src, ""))["S006"] {
			t.Error("expected S006 for a 3-stage pipeline ending in bash")
		}
	})
}

func TestSudo(t *testing.T) {
	if !ruleIDs(analyze(t, "FROM alpine\nRUN sudo apt-get install -y curl\nUSER app\n", ""))["S008"] {
		t.Error("expected S008 for sudo usage")
	}
}

func TestSensitiveFileCopy(t *testing.T) {
	if !ruleIDs(analyze(t, "FROM alpine\nCOPY id_rsa /root/.ssh/id_rsa\nUSER app\n", ""))["S009"] {
		t.Error("expected S009 for copying an ssh private key")
	}
	if ruleIDs(analyze(t, "FROM alpine\nCOPY app.py /app/app.py\nUSER app\n", ""))["S009"] {
		t.Error("did not expect S009 for an ordinary source file")
	}
}

func TestCrossLayerPersistence(t *testing.T) {
	src := "FROM alpine\nCOPY id_rsa /root/.ssh/id_rsa\nRUN rm /root/.ssh/id_rsa\nUSER app\n"
	if !ruleIDs(analyze(t, src, ""))["S017"] {
		t.Error("expected S017 when a sensitive file is copied then removed in a later instruction")
	}

	t.Run("same-instruction write+remove is fine", func(t *testing.T) {
		src := "FROM alpine\nRUN echo x > /root/.ssh/id_rsa && rm /root/.ssh/id_rsa\nUSER app\n"
		if ruleIDs(analyze(t, src, ""))["S017"] {
			t.Error("did not expect S017 when write and remove happen in the same RUN layer")
		}
	})

	t.Run("removed via directory rm -rf", func(t *testing.T) {
		src := "FROM alpine\nCOPY id_rsa /root/.ssh/id_rsa\nRUN rm -rf /root/.ssh\nUSER app\n"
		if !ruleIDs(analyze(t, src, ""))["S017"] {
			t.Error("expected S017 when the sensitive file's directory is later rm -rf'd")
		}
	})

	t.Run("write via RUN redirect then remove", func(t *testing.T) {
		src := "FROM alpine\nARG TOKEN\nRUN echo $TOKEN > /app/.env\nRUN rm /app/.env\nUSER app\n"
		if !ruleIDs(analyze(t, src, ""))["S017"] {
			t.Error("expected S017 for a RUN-written sensitive file removed in a later RUN")
		}
	})

	t.Run("no removal means no finding", func(t *testing.T) {
		src := "FROM alpine\nCOPY id_rsa /root/.ssh/id_rsa\nUSER app\n"
		if ruleIDs(analyze(t, src, ""))["S017"] {
			t.Error("did not expect S017 when the file is never removed")
		}
	})
}

func TestCrossStageSecretLeak(t *testing.T) {
	t.Run("directory copy pulls in a leftover secret", func(t *testing.T) {
		src := "FROM golang AS builder\n" +
			"COPY id_rsa /root/.ssh/id_rsa\n" +
			"RUN go build -o /out/app .\n" +
			"\nFROM alpine\n" +
			"COPY --from=builder /out/app /app\n" +
			"COPY --from=builder /root/.ssh /stolen\n" +
			"USER app\n"
		if !ruleIDs(analyze(t, src, ""))["S024"] {
			t.Error("expected S024 when a later stage copies a directory still containing a leftover secret")
		}
	})

	t.Run("exact file copy pulls in a leftover secret", func(t *testing.T) {
		src := "FROM golang AS builder\n" +
			"COPY id_rsa /root/.ssh/id_rsa\n" +
			"RUN go build -o /out/app .\n" +
			"\nFROM alpine\n" +
			"COPY --from=builder /root/.ssh/id_rsa /stolen\n" +
			"USER app\n"
		if !ruleIDs(analyze(t, src, ""))["S024"] {
			t.Error("expected S024 for an exact-path copy of a leftover secret")
		}
	})

	t.Run("cleaned up before stage end is fine", func(t *testing.T) {
		src := "FROM golang AS builder\n" +
			"COPY id_rsa /root/.ssh/id_rsa\n" +
			"RUN go build -o /out/app .\n" +
			"RUN rm -rf /root/.ssh\n" +
			"\nFROM alpine\n" +
			"COPY --from=builder /out/app /app\n" +
			"USER app\n"
		if ruleIDs(analyze(t, src, ""))["S024"] {
			t.Error("did not expect S024 when the secret is removed before the stage ends, regardless of instruction order")
		}
	})

	t.Run("copy that does not overlap the secret path is fine", func(t *testing.T) {
		src := "FROM golang AS builder\n" +
			"COPY id_rsa /root/.ssh/id_rsa\n" +
			"RUN go build -o /out/app .\n" +
			"\nFROM alpine\n" +
			"COPY --from=builder /out/app /app\n" +
			"USER app\n"
		if ruleIDs(analyze(t, src, ""))["S024"] {
			t.Error("did not expect S024 when the COPY source doesn't overlap the secret's path")
		}
	})

	t.Run("single stage never flagged", func(t *testing.T) {
		if ruleIDs(analyze(t, "FROM alpine\nCOPY id_rsa /root/.ssh/id_rsa\nUSER app\n", ""))["S024"] {
			t.Error("did not expect S024 for a single-stage build")
		}
	})
}

func TestSensitivePort(t *testing.T) {
	if !ruleIDs(analyze(t, "FROM alpine\nEXPOSE 22\nUSER app\n", ""))["S010"] {
		t.Error("expected S010 for EXPOSE 22")
	}
	if ruleIDs(analyze(t, "FROM alpine\nEXPOSE 8080\nUSER app\n", ""))["S010"] {
		t.Error("did not expect S010 for an ordinary application port")
	}
}

func TestUnpinnedPackageInstall(t *testing.T) {
	if !ruleIDs(analyze(t, "FROM ubuntu\nRUN apt-get install -y curl\nUSER app\n", ""))["S011"] {
		t.Error("expected S011 for unpinned apt-get install")
	}
	if ruleIDs(analyze(t, "FROM ubuntu\nRUN apt-get install -y curl=7.81.0-1ubuntu1\nUSER app\n", ""))["S011"] {
		t.Error("did not expect S011 when the package version is pinned")
	}
	t.Run("apk add", func(t *testing.T) {
		if !ruleIDs(analyze(t, "FROM alpine\nRUN apk add curl\nUSER app\n", ""))["S011"] {
			t.Error("expected S011 for unpinned apk add")
		}
		if ruleIDs(analyze(t, "FROM alpine\nRUN apk add curl=8.5.0-r0\nUSER app\n", ""))["S011"] {
			t.Error("did not expect S011 when the apk package version is pinned")
		}
	})
}

func TestInsecureTLS(t *testing.T) {
	if !ruleIDs(analyze(t, "FROM alpine\nRUN curl -k https://example.com/x.sh -o x.sh\nUSER app\n", ""))["S012"] {
		t.Error("expected S012 for curl -k")
	}
	if ruleIDs(analyze(t, "FROM alpine\nRUN curl https://example.com/x.sh -o x.sh\nUSER app\n", ""))["S012"] {
		t.Error("did not expect S012 for a plain curl invocation")
	}
}

func TestDockerignoreMissing(t *testing.T) {
	dir := t.TempDir()
	src := "FROM alpine\nCOPY . .\nUSER app\n"
	if !ruleIDs(analyze(t, src, dir))["S019"] {
		t.Error("expected S019 for a broad COPY with no .dockerignore")
	}
}

func TestDockerignoreExcludesSecrets(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".dockerignore"), []byte(".git\n.env\nid_rsa\n.ssh\n.aws\n.pem\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	src := "FROM alpine\nCOPY . .\nUSER app\n"
	if ruleIDs(analyze(t, src, dir))["S019"] {
		t.Error("did not expect S019 when .dockerignore covers all the checked secret paths")
	}
}

func TestDockerignoreOnlyMattersForBroadCopy(t *testing.T) {
	dir := t.TempDir()
	src := "FROM alpine\nCOPY package.json ./\nUSER app\n"
	if ruleIDs(analyze(t, src, dir))["S019"] {
		t.Error("did not expect S019 when COPY is narrow, regardless of .dockerignore")
	}
}

func TestDuplicateStartupInstructions(t *testing.T) {
	t.Run("duplicate CMD", func(t *testing.T) {
		src := "FROM alpine\nCMD [\"one\"]\nCMD [\"two\"]\nUSER app\n"
		if !ruleIDs(analyze(t, src, ""))["S020"] {
			t.Error("expected S020 for a duplicate CMD")
		}
	})
	t.Run("duplicate ENTRYPOINT", func(t *testing.T) {
		src := "FROM alpine\nENTRYPOINT [\"one\"]\nENTRYPOINT [\"two\"]\nUSER app\n"
		if !ruleIDs(analyze(t, src, ""))["S020"] {
			t.Error("expected S020 for a duplicate ENTRYPOINT")
		}
	})
	t.Run("single CMD and ENTRYPOINT together is fine", func(t *testing.T) {
		src := "FROM alpine\nENTRYPOINT [\"one\"]\nCMD [\"two\"]\nUSER app\n"
		if ruleIDs(analyze(t, src, ""))["S020"] {
			t.Error("did not expect S020 for one CMD and one ENTRYPOINT")
		}
	})
	t.Run("resets per stage", func(t *testing.T) {
		src := "FROM golang AS builder\nCMD [\"one\"]\nCMD [\"two\"]\n\nFROM alpine\nCMD [\"three\"]\nUSER app\n"
		findings := analyze(t, src, "")
		count := 0
		for _, f := range findings {
			if f.RuleID == "S020" {
				count++
			}
		}
		// only the builder stage's duplicate should be flagged
		if count != 1 {
			t.Errorf("expected exactly 1 S020 finding, got %d: %+v", count, findings)
		}
	})
	t.Run("duplicate HEALTHCHECK", func(t *testing.T) {
		src := "FROM alpine\nHEALTHCHECK CMD curl -f http://localhost/ || exit 1\nHEALTHCHECK NONE\nUSER app\n"
		if !ruleIDs(analyze(t, src, ""))["S025"] {
			t.Error("expected S025 for a duplicate HEALTHCHECK")
		}
		if ruleIDs(analyze(t, src, ""))["S020"] {
			t.Error("did not expect S020 to fire for a duplicate HEALTHCHECK")
		}
	})
	t.Run("single HEALTHCHECK is fine", func(t *testing.T) {
		src := "FROM alpine\nHEALTHCHECK CMD curl -f http://localhost/ || exit 1\nUSER app\n"
		if ruleIDs(analyze(t, src, ""))["S025"] {
			t.Error("did not expect S025 for a single HEALTHCHECK")
		}
	})
}

func TestMaintainerDeprecated(t *testing.T) {
	if !ruleIDs(analyze(t, "FROM alpine\nMAINTAINER me@example.com\nUSER app\n", ""))["S026"] {
		t.Error("expected S026 for MAINTAINER")
	}
	if ruleIDs(analyze(t, "FROM alpine\nLABEL maintainer=\"me@example.com\"\nUSER app\n", ""))["S026"] {
		t.Error("did not expect S026 when using LABEL instead")
	}
}

func TestShellFormStartup(t *testing.T) {
	if !ruleIDs(analyze(t, "FROM alpine\nUSER app\nCMD npm start\n", ""))["S021"] {
		t.Error("expected S021 for shell-form CMD")
	}
	if ruleIDs(analyze(t, "FROM alpine\nUSER app\nCMD [\"npm\", \"start\"]\n", ""))["S021"] {
		t.Error("did not expect S021 for exec-form CMD")
	}
	if !ruleIDs(analyze(t, "FROM alpine\nUSER app\nENTRYPOINT /entrypoint.sh\n", ""))["S021"] {
		t.Error("expected S021 for shell-form ENTRYPOINT")
	}
	t.Run("only checks final stage", func(t *testing.T) {
		src := "FROM golang AS builder\nCMD npm start\n\nFROM alpine\nCMD [\"node\", \"server.js\"]\nUSER app\n"
		if ruleIDs(analyze(t, src, ""))["S021"] {
			t.Error("did not expect S021 for a non-final stage's shell-form CMD")
		}
	})
}

func TestStartsCorrectly(t *testing.T) {
	if !ruleIDs(analyze(t, "RUN echo hi\nFROM alpine\nUSER app\n", ""))["S022"] {
		t.Error("expected S022 when the file doesn't start with FROM or ARG")
	}
	if ruleIDs(analyze(t, "FROM alpine\nUSER app\n", ""))["S022"] {
		t.Error("did not expect S022 when the file starts with FROM")
	}
	if ruleIDs(analyze(t, "ARG VERSION=1.0\nFROM alpine:$VERSION\nUSER app\n", ""))["S022"] {
		t.Error("did not expect S022 when the file starts with a global ARG before FROM")
	}
}

func TestExposePortRange(t *testing.T) {
	if !ruleIDs(analyze(t, "FROM alpine\nEXPOSE 99999\nUSER app\n", ""))["S023"] {
		t.Error("expected S023 for an out-of-range EXPOSE port")
	}
	if ruleIDs(analyze(t, "FROM alpine\nEXPOSE 8080\nUSER app\n", ""))["S023"] {
		t.Error("did not expect S023 for a valid EXPOSE port")
	}
	if ruleIDs(analyze(t, "FROM alpine\nEXPOSE 65535\nUSER app\n", ""))["S023"] {
		t.Error("did not expect S023 for the maximum valid port")
	}
}

func TestFindingOrderIsDeterministic(t *testing.T) {
	src := "FROM alpine\n" +
		"ARG API_SECRET_TOKEN=placeholder\n" +
		"ARG DB_PASSWORD=placeholder2\n" +
		"ENV AWS_KEY=AKIAIOSFODNN7EXAMPLE GITHUB_TOKEN=ghp_aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa\n" +
		"RUN echo \"$API_SECRET_TOKEN $DB_PASSWORD\"\n" +
		"USER app\n"

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

func TestNonDockerfileInputIsIgnored(t *testing.T) {
	findings, err := New().Analyze(analyzer.Context{})
	if err != nil {
		t.Fatalf("Analyze: %v", err)
	}
	if findings != nil {
		t.Errorf("expected no findings for a non-dockerfile ParsedFile, got %v", findings)
	}
}
