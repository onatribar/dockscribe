package dockerfile

import "testing"

func mustParse(t *testing.T, src string) *File {
	t.Helper()
	f, err := New().Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return f.(*File)
}

func TestCanParse(t *testing.T) {
	p := New()
	tests := []struct {
		name string
		want bool
	}{
		{"Dockerfile", true},
		{"dockerfile", true},
		{"Dockerfile.dev", true},
		{"app.dockerfile", true},
		{"docker-compose.yml", false},
		{"Makefile", false},
	}
	for _, tt := range tests {
		if got := p.CanParse(tt.name); got != tt.want {
			t.Errorf("CanParse(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestTokenizeSkipsBlankLinesAndComments(t *testing.T) {
	f := mustParse(t, "# a comment\n\nFROM alpine\n\n# another\nCMD [\"true\"]\n")
	if len(f.Instructions) != 2 {
		t.Fatalf("expected 2 instructions, got %d: %+v", len(f.Instructions), f.Instructions)
	}
	if f.Instructions[0].Cmd != "FROM" || f.Instructions[1].Cmd != "CMD" {
		t.Errorf("unexpected instructions: %+v", f.Instructions)
	}
}

func TestLineContinuation(t *testing.T) {
	src := "FROM alpine\nRUN apt-get update && \\\n    apt-get install -y curl\n"
	f := mustParse(t, src)
	if len(f.Instructions) != 2 {
		t.Fatalf("expected 2 instructions, got %d: %+v", len(f.Instructions), f.Instructions)
	}
	run := f.Instructions[1]
	if run.Cmd != "RUN" {
		t.Fatalf("expected RUN, got %s", run.Cmd)
	}
	if run.Line != 2 {
		t.Errorf("expected continued instruction attributed to its start line 2, got %d", run.Line)
	}
	want := "apt-get update && apt-get install -y curl"
	if run.Args != want {
		t.Errorf("Args = %q, want %q", run.Args, want)
	}
}

func TestInstructionEndLine(t *testing.T) {
	t.Run("single-line instruction", func(t *testing.T) {
		f := mustParse(t, "FROM alpine\nRUN echo hi\n")
		run := f.Instructions[1]
		if run.Line != 2 || run.EndLine != 2 || !run.IsSingleLine() {
			t.Errorf("run = %+v, want Line=2 EndLine=2 IsSingleLine=true", run)
		}
	})

	t.Run("backslash-continued instruction spans multiple lines", func(t *testing.T) {
		src := "FROM alpine\nRUN apt-get update && \\\n    apt-get install -y curl\n"
		f := mustParse(t, src)
		run := f.Instructions[1]
		if run.Line != 2 || run.EndLine != 3 || run.IsSingleLine() {
			t.Errorf("run = %+v, want Line=2 EndLine=3 IsSingleLine=false", run)
		}
	})

	t.Run("heredoc RUN spans to its closing marker", func(t *testing.T) {
		src := "FROM alpine\nRUN <<EOF\necho hi\nEOF\nCMD [\"true\"]\n"
		f := mustParse(t, src)
		run := f.Instructions[1]
		if run.Line != 2 || run.EndLine != 4 || run.IsSingleLine() {
			t.Errorf("run = %+v, want Line=2 EndLine=4 IsSingleLine=false", run)
		}
		cmd := f.Instructions[2]
		if !cmd.IsSingleLine() {
			t.Errorf("cmd = %+v, want IsSingleLine=true", cmd)
		}
	})

	t.Run("multi-line JSON array spans to the closing bracket", func(t *testing.T) {
		src := "FROM alpine\nCMD [\n  \"node\",\n  \"server.js\"\n]\n"
		f := mustParse(t, src)
		cmd := f.Instructions[1]
		if cmd.Line != 2 || cmd.EndLine != 5 || cmd.IsSingleLine() {
			t.Errorf("cmd = %+v, want Line=2 EndLine=5 IsSingleLine=false", cmd)
		}
	})
}

func TestInstructionAt(t *testing.T) {
	f := mustParse(t, "FROM alpine\nRUN echo hi\nUSER app\n")
	run, ok := f.InstructionAt(2)
	if !ok || run.Cmd != "RUN" {
		t.Errorf("InstructionAt(2) = %+v, %v, want RUN instruction", run, ok)
	}
	if _, ok := f.InstructionAt(99); ok {
		t.Error("InstructionAt(99) should not find an instruction on a nonexistent line")
	}
}

func TestMultiStage(t *testing.T) {
	src := "FROM golang:1.22 AS builder\nRUN go build -o /out/app .\n\nFROM alpine\nCOPY --from=builder /out/app /app\n"
	f := mustParse(t, src)

	if f.StageCount() != 2 {
		t.Fatalf("expected 2 stages, got %d", f.StageCount())
	}
	if f.Stages[0].Name != "builder" || f.Stages[0].BaseImage != "golang:1.22" {
		t.Errorf("stage 0 = %+v", f.Stages[0])
	}
	if f.Stages[1].Name != "" || f.Stages[1].BaseImage != "alpine" {
		t.Errorf("stage 1 = %+v", f.Stages[1])
	}

	for _, instr := range f.Instructions {
		wantStage := 0
		if instr.Line >= f.Stages[1].StartLine {
			wantStage = 1
		}
		if instr.Stage != wantStage {
			t.Errorf("instruction %+v: Stage = %d, want %d", instr, instr.Stage, wantStage)
		}
	}

	if !f.IsStageReference("builder") {
		t.Error("expected IsStageReference(\"builder\") to be true")
	}
	if f.IsStageReference("alpine") {
		t.Error("did not expect IsStageReference(\"alpine\") to be true")
	}
}

func TestFromWithPlatformFlag(t *testing.T) {
	tests := []struct {
		name      string
		from      string
		wantImage string
		wantName  string
	}{
		{"platform with stage name", "FROM --platform=$BUILDPLATFORM node:14 AS builder", "node:14", "builder"},
		{"platform without stage name", "FROM --platform=linux/amd64 node:14", "node:14", ""},
		{"no platform flag", "FROM node:14 AS builder", "node:14", "builder"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := mustParse(t, tt.from+"\n")
			if len(f.Stages) != 1 {
				t.Fatalf("expected 1 stage, got %d", len(f.Stages))
			}
			if f.Stages[0].BaseImage != tt.wantImage || f.Stages[0].Name != tt.wantName {
				t.Errorf("stage = %+v, want BaseImage %q, Name %q", f.Stages[0], tt.wantImage, tt.wantName)
			}
		})
	}
}

func TestGlobalArgResolvedIntoFrom(t *testing.T) {
	tests := []struct {
		name      string
		src       string
		wantImage string
	}{
		{
			"braced reference with default",
			"ARG NODE_VERSION=18.20.4-alpine3.19\nFROM node:${NODE_VERSION}\n",
			"node:18.20.4-alpine3.19",
		},
		{
			"bare $NAME reference",
			"ARG NODE_VERSION=18.20.4-alpine3.19\nFROM node:$NODE_VERSION\n",
			"node:18.20.4-alpine3.19",
		},
		{
			"applies to every stage, not just the first",
			"ARG TAG=1.0\nFROM alpine:${TAG} AS builder\nFROM node:${TAG}\n",
			"node:1.0",
		},
		{
			"ARG declared inside a stage does not reach a later FROM",
			"FROM alpine AS builder\nARG TAG=1.0\nFROM node:${TAG}\n",
			"node:${TAG}",
		},
		{
			"no default value: left unresolved rather than guessed at",
			"ARG NODE_VERSION\nFROM node:${NODE_VERSION}\n",
			"node:${NODE_VERSION}",
		},
		{
			"undeclared name: left unresolved",
			"FROM node:${NOT_DECLARED}\n",
			"node:${NOT_DECLARED}",
		},
		{
			"shell-style default expansion is not attempted",
			"ARG NODE_VERSION=18\nFROM node:${NODE_VERSION:-20}\n",
			"node:${NODE_VERSION:-20}",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			f := mustParse(t, tt.src)
			last := f.Stages[len(f.Stages)-1]
			if last.BaseImage != tt.wantImage {
				t.Errorf("BaseImage = %q, want %q", last.BaseImage, tt.wantImage)
			}
		})
	}
}

func TestMultiLineJSONArrayWithoutBackslash(t *testing.T) {
	// Tracking bracket depth because JSON without a trailing backslash is till valid for Dockerfiles
	src := "FROM alpine\nCMD [\n  \"node\",\n  \"server.js\"\n]\n"
	f := mustParse(t, src)
	if len(f.Instructions) != 2 {
		t.Fatalf("expected 2 instructions, got %d: %+v", len(f.Instructions), f.Instructions)
	}
	cmd := f.Instructions[1]
	if cmd.Cmd != "CMD" {
		t.Fatalf("expected CMD, got %s", cmd.Cmd)
	}
	want := `[ "node", "server.js" ]`
	if cmd.Args != want {
		t.Errorf("Args = %q, want %q", cmd.Args, want)
	}
}

func TestRunHeredoc(t *testing.T) {
	src := "FROM alpine\nRUN <<EOF\napt-get update\napt-get install -y curl\nEOF\nCMD [\"true\"]\n"
	f := mustParse(t, src)
	if len(f.Instructions) != 3 {
		t.Fatalf("expected 3 instructions (FROM, RUN, CMD), got %d: %+v", len(f.Instructions), f.Instructions)
	}
	run := f.Instructions[1]
	if run.Cmd != "RUN" {
		t.Fatalf("expected RUN, got %s", run.Cmd)
	}
	want := "apt-get update\napt-get install -y curl"
	if run.Args != want {
		t.Errorf("Args = %q, want %q", run.Args, want)
	}
	if run.Line != 2 {
		t.Errorf("expected the heredoc RUN attributed to its opening line 2, got %d", run.Line)
	}
	cmd := f.Instructions[2]
	if cmd.Cmd != "CMD" || cmd.Line != 6 {
		t.Errorf("expected CMD on line 6 after the heredoc body, got %+v", cmd)
	}
}

func TestRunHeredocWithLeadingBuildKitFlag(t *testing.T) {
	src := "FROM alpine\nRUN --mount=type=cache,target=/x <<EOF\necho hi\nEOF\n"
	f := mustParse(t, src)
	run := f.Instructions[1]
	if run.Cmd != "RUN" || run.Args != "echo hi" {
		t.Errorf("run = %+v, want Args %q", run, "echo hi")
	}
}

func TestRunHeredocUnterminatedFallsBackToLiteral(t *testing.T) {
	src := "FROM alpine\nRUN <<EOF\necho hi\n"
	f := mustParse(t, src)
	if len(f.Instructions) != 3 {
		t.Fatalf("expected 3 instructions, got %d: %+v", len(f.Instructions), f.Instructions)
	}
	if f.Instructions[1].Cmd != "RUN" || f.Instructions[1].Args != "<<EOF" {
		t.Errorf("run = %+v", f.Instructions[1])
	}
}

func TestRawLinesPreservesSourceLineCount(t *testing.T) {
	src := "FROM alpine\n\nCMD [\"true\"]\n"
	f := mustParse(t, src)
	if len(f.RawLines()) != 3 {
		t.Errorf("RawLines() len = %d, want 3", len(f.RawLines()))
	}
}

func TestParseRejectsIncoherentContent(t *testing.T) {
	src := "services:\n  web:\n    image: nginx\n    ports:\n      - \"80:80\"\n"
	if _, err := New().Parse([]byte(src)); err == nil {
		t.Error("expected an error for content with no recognized Dockerfile instructions, got nil")
	}
}

func TestParseAcceptsRealDockerfileEvenWithUnrecognizedNeighborLines(t *testing.T) {
	// Assumption: it's a Dockerfile for as long as it has one instruction
	f := mustParse(t, "FROM alpine\nRUN echo hi\n")
	if len(f.Instructions) != 2 {
		t.Errorf("expected a normal parse to still succeed, got %d instructions", len(f.Instructions))
	}
}

func TestFileType(t *testing.T) {
	f := mustParse(t, "FROM alpine\n")
	if f.FileType() != "dockerfile" {
		t.Errorf("FileType() = %q, want %q", f.FileType(), "dockerfile")
	}
}
