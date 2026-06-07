package dockerfile

import (
	"bufio"
	"bytes"
	"path/filepath"
	"strings"

	"github.com/onatribar/dockscribe/pkg/parser"
)

// Instruction is a single tokenised Dockerfile instruction
type Instruction struct {
	Line  int    // 1-based source line number of the instruction's first line
	Cmd   string // uppercased instruction keyword, e.g. "FROM", "RUN"
	Args  string // raw remainder of the instruction, whitespace-trimmed
	Stage int    // index into File.Stages this instruction belongs to (-1 before any FROM)
}

// Stage describes one `FROM` build stage.
type Stage struct {
	Index     int
	BaseImage string // e.g. "node:18-alpine"
	Name      string // the `AS <name>` alias, if there is any
	StartLine int
}

// File is the parsed representation of a Dockerfile.
type File struct {
	lines        []string
	Instructions []Instruction
	Stages       []Stage
}

func (f *File) FileType() string {
	return "dockerfile"
}
func (f *File) RawLines() []string {
	return f.lines
}

func (f *File) StageCount() int {
	return len(f.Stages)
}

// Parser parses Dockerfiles
type Parser struct{}

func New() *Parser { return &Parser{} }

func (p *Parser) CanParse(filename string) bool {
	base := strings.ToLower(filepath.Base(filename))
	return base == "dockerfile" ||
		strings.HasPrefix(base, "dockerfile.") ||
		strings.HasSuffix(base, ".dockerfile")
}

func (p *Parser) Parse(src []byte) (parser.ParsedFile, error) {
	lines := splitLines(src)
	f := &File{lines: lines}

	stage := -1
	for _, instr := range tokenize(lines) {
		if instr.Cmd == "FROM" {
			stage++
			image, name := parseFromArgs(instr.Args)
			f.Stages = append(f.Stages, Stage{
				Index:     stage,
				BaseImage: image,
				Name:      name,
				StartLine: instr.Line,
			})
		}
		instr.Stage = stage
		f.Instructions = append(f.Instructions, instr)
	}
	return f, nil
}

func splitLines(src []byte) []string {
	var lines []string
	scanner := bufio.NewScanner(bytes.NewReader(src))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines
}

// tokenize joins line continuations, skips comments and blank lines
// splits each logical instruction into a keyword and its argument string
func tokenize(lines []string) []Instruction {
	var out []Instruction

	var buf strings.Builder
	startLine := 0

	flush := func() {
		if buf.Len() == 0 {
			return
		}
		text := strings.TrimSpace(buf.String())
		buf.Reset()
		if text == "" {
			return
		}
		cmd, args := splitInstruction(text)
		if cmd == "" {
			return
		}
		out = append(out, Instruction{Line: startLine, Cmd: cmd, Args: args})
	}

	for i, raw := range lines {
		lineNo := i + 1
		trimmed := strings.TrimSpace(raw)

		if buf.Len() == 0 {
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}
			startLine = lineNo
		}

		content := trimmed
		continued := strings.HasSuffix(content, "\\")
		if continued {
			content = strings.TrimSpace(strings.TrimSuffix(content, "\\"))
		}

		if buf.Len() > 0 {
			buf.WriteByte(' ')
		}
		buf.WriteString(content)

		if !continued {
			flush()
		}
	}
	flush()

	return out
}

// separates the leading keyword from the rest of an instruction line
// e.g. "RUN npm ci" -> ("RUN", "npm ci").
func splitInstruction(text string) (cmd, args string) {
	fields := strings.SplitN(text, " ", 2)
	cmd = strings.ToUpper(fields[0])
	if len(fields) == 2 {
		args = strings.TrimSpace(fields[1])
	}
	return cmd, args
}

// extracts the base image and optional stage alias from a FROM instruction's arguments
// e.g. "node:18-alpine AS builder".
func parseFromArgs(args string) (image, name string) {
	fields := strings.Fields(args)
	if len(fields) == 0 {
		return "", ""
	}
	image = fields[0]
	for i := 1; i < len(fields)-1; i++ {
		if strings.EqualFold(fields[i], "AS") {
			name = fields[i+1]
			break
		}
	}
	return image, name
}
