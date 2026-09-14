// This file is the package's public surface.
package dockerfile

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/onatribar/dockscribe/pkg/parser"
)

// knownInstructions are every keyword the Dockerfile spec recognizes.
// A non-empty file matching none of them is reliably not a Dockerfile at all.
var knownInstructions = map[string]bool{
	"FROM": true, "RUN": true, "CMD": true, "LABEL": true, "MAINTAINER": true,
	"EXPOSE": true, "ENV": true, "ADD": true, "COPY": true, "ENTRYPOINT": true,
	"VOLUME": true, "USER": true, "WORKDIR": true, "ARG": true, "ONBUILD": true,
	"STOPSIGNAL": true, "HEALTHCHECK": true, "SHELL": true,
}

// Instruction is a single tokenised Dockerfile instruction
type Instruction struct {
	Line    int    // 1-based source line number of the instruction's first line
	EndLine int    // 1-based source line number of the instruction's last line (== Line for a single-physical-line instruction)
	Cmd     string // upper-cased instruction keyword (e.g. "FROM", "RUN")
	Args    string // raw remainder of the instruction trimmed of whitespace
	Stage   int    // index into File.Stages this instruction belongs to (-1 before any FROM)
}

// Does the instruction live in a single line? Ignores backslash continuation or heredoc bodies.
func (i Instruction) IsSingleLine() bool {
	return i.EndLine == i.Line
}

// Stage := one FROM build stage.
type Stage struct {
	Index     int
	BaseImage string // e.g. "node:18-alpine"
	Name      string // the `AS <name>` alias (if any)
	StartLine int
}

// File := parsed representation of a Dockerfile.
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

// returns whether any COPY copies the whole build context rather than a specific path
func (f *File) HasBroadCopy() bool {
	for _, instr := range f.Instructions {
		if instr.Cmd != "COPY" {
			continue
		}

		_, positional := SplitFlags(instr.Args)
		if len(positional) < 2 {
			continue
		}
		for _, s := range positional[:len(positional)-1] {
			if IsBroadCopySource(s) {
				return true
			}
		}
	}
	return false
}

// reports whether image names an earlier stage in f (e.g. "FROM builder") rather than a pulled image
func (f *File) IsStageReference(image string) bool {
	for _, s := range f.Stages {
		if s.Name != "" && s.Name == image {
			return true
		}
	}
	return false
}

// returns the value of the last USER instruction in f's final build stage, or "" if none was set
// (Docker's own default is root. see IsRootUser, which treats "" the same way).
func (f *File) FinalStageUser() string {
	if len(f.Stages) == 0 {
		return ""
	}
	finalStage := len(f.Stages) - 1
	user := ""
	for _, instr := range f.Instructions {
		if instr.Stage == finalStage && instr.Cmd == "USER" {
			user = instr.Args
		}
	}
	return user
}

// returns the instruction starting at the given 1-based source line, if any.
func (f *File) InstructionAt(line int) (Instruction, bool) {
	for _, instr := range f.Instructions {
		if instr.Line == line {
			return instr, true
		}
	}
	return Instruction{}, false
}

// Parser parses Dockerfiles (what else)
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

	tokens := tokenize(lines)
	if err := checkCoherent(tokens); err != nil {
		return nil, err
	}

	globalArgs := collectGlobalArgs(tokens)

	stage := -1
	for _, instr := range tokens {
		if instr.Cmd == "FROM" {
			stage++
			image, name := parseFromArgs(instr.Args)
			f.Stages = append(f.Stages, Stage{
				Index:     stage,
				BaseImage: resolveImageRef(image, globalArgs),
				Name:      name,
				StartLine: instr.Line,
			})
		}
		instr.Stage = stage
		f.Instructions = append(f.Instructions, instr)
	}
	return f, nil
}

// gathers name -> default value for every ARG declared before the first FROM
// These are the only ARGs a FROM can reference (e.g. `ARG VERSION=18` then `FROM node:${VERSION}`)
// a stage-scoped ARG never reaches a FROM line.
func collectGlobalArgs(tokens []Instruction) map[string]string {
	args := map[string]string{}
	for _, instr := range tokens {
		if instr.Cmd == "FROM" {
			break
		}
		if instr.Cmd == "ARG" {
			name, value := ParseArgDeclaration(instr.Args)
			args[name] = value
		}
	}
	return args
}

// splits an ARG instruction's argument string into the declared name and default value
// e.g. "VERSION=18-alpine" -> ("VERSION", "18-alpine") or a bare "VERSION" (no default) -> ("VERSION", "").
func ParseArgDeclaration(args string) (name, value string) {
	name, value = args, ""
	if i := strings.IndexByte(args, '='); i >= 0 {
		name, value = args[:i], strings.Trim(args[i+1:], `"'`)
	}
	return strings.TrimSpace(name), value
}

// rejects a non-empty file where no tokenized line matches a real Dockerfile keyword
// content that merely lives in a file named like a Dockerfile, not a Dockerfile with a defect.
func checkCoherent(tokens []Instruction) error {
	if len(tokens) == 0 {
		return nil // empty file := same treatment as an empty Dockerfile always got
	}
	for _, instr := range tokens {
		if knownInstructions[instr.Cmd] {
			return nil
		}
	}
	return fmt.Errorf("doesn't look like a Dockerfile: no recognized instructions found (line %d starts with %q)", tokens[0].Line, tokens[0].Cmd)
}
