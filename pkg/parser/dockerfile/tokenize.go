package dockerfile

import (
	"bufio"
	"bytes"
	"regexp"
	"strings"
)

func splitLines(src []byte) []string {
	var lines []string
	scanner := bufio.NewScanner(bytes.NewReader(src))
	scanner.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for scanner.Scan() {
		lines = append(lines, scanner.Text())
	}
	return lines
}

// matches a RUN instruction's arguments when they are nothing but a heredoc opener
// e.g. "<<EOF", "<<-EOF", `<<"EOF"`, "--mount=type=cache,target=/x <<EOF".
var heredocRe = regexp.MustCompile(`^(?:--\S+\s+)*<<-?['"]?([A-Za-z_][A-Za-z0-9_]*)['"]?$`)

// tokenize joins line continuations, skips comments and blank lines
// splits each logical instruction into a keyword and argument string
func tokenize(lines []string) []Instruction {
	var out []Instruction

	var buf strings.Builder
	startLine := 0
	bracketDepth := 0

	flush := func(endLine int) {
		if buf.Len() == 0 {
			return
		}

		text := strings.TrimSpace(buf.String())
		buf.Reset()
		bracketDepth = 0
		if text == "" {
			return
		}

		cmd, args := splitInstruction(text)
		if cmd == "" {
			return
		}

		out = append(out, Instruction{Line: startLine, EndLine: endLine, Cmd: cmd, Args: args})
	}

	i := 0
	for i < len(lines) {
		lineNo := i + 1
		trimmed := strings.TrimSpace(lines[i])

		if buf.Len() == 0 {
			// Not mid-instruction: a blank line or comment here is just
			// noise between instructions, not part of one.
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				i++
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
		bracketDepth += bracketDelta(content)
		i++

		if continued || bracketDepth > 0 {
			// Backslash continuation, or still inside an unclosed JSON string
			// then the instruction isn't finished yet, keep accumulating
			continue
		}

		if cmd, args := splitInstruction(strings.TrimSpace(buf.String())); cmd == "RUN" {
			if m := heredocRe.FindStringSubmatch(args); m != nil {
				if body, end, ok := consumeHeredoc(lines, i, m[1]); ok {
					out = append(out, Instruction{Line: startLine, EndLine: end + 1, Cmd: "RUN", Args: body})
					buf.Reset()
					bracketDepth = 0
					i = end + 1
					continue
				}
			}
		}

		flush(i)
	}
	flush(len(lines))

	return out
}

func bracketDelta(s string) int {
	delta := 0
	for _, r := range s {
		switch r {
		case '[':
			delta++
		case ']':
			delta--
		}
	}
	return delta
}

// read lines from the 0-based index from as a heredoc body, stopping at the line matching marker
// ok is false if the file ended first, meaning not a real heredoc, caller falls back to normal parsing
func consumeHeredoc(lines []string, from int, marker string) (body string, end int, ok bool) {
	var b strings.Builder
	for i := from; i < len(lines); i++ {
		if strings.TrimSpace(lines[i]) == marker {
			return b.String(), i, true
		}
		if b.Len() > 0 {
			b.WriteByte('\n')
		}
		b.WriteString(lines[i])
	}
	return "", 0, false
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
// e.g. "node:18-alpine AS builder"
// a leading --platform flag is skipped first, or it'd be mistaken for the image
func parseFromArgs(args string) (image, name string) {
	fields := strings.Fields(args)
	i := 0

	for i < len(fields) && strings.HasPrefix(fields[i], "--") {
		i++
	}
	if i >= len(fields) {
		return "", ""
	}

	image = fields[i]
	for j := i + 1; j < len(fields)-1; j++ {
		if strings.EqualFold(fields[j], "AS") {
			name = fields[j+1]
			break
		}
	}

	return image, name
}

// looks for a complete "$NAME" or "${NAME}" reference only
// deliberately not shell-style "${NAME:-default}" since a partial match on "${NAME"
// would substitute into the middle of the expression and produce nonsense.
// an unsupported expansion just doesn't match and passes through resolveImageRef unresolved.
var argRefRe = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}|\$([A-Za-z_][A-Za-z0-9_]*)`)

// substitutes any $NAME/${NAME} reference in image with its value from globalArgs when known
// An ARG with no default (or one not seen as global) is left exactly as written, so no guessing games.
func resolveImageRef(image string, globalArgs map[string]string) string {
	return argRefRe.ReplaceAllStringFunc(image, func(match string) string {
		groups := argRefRe.FindStringSubmatch(match)
		name := groups[1]
		if name == "" {
			name = groups[2]
		}
		if v, ok := globalArgs[name]; ok && v != "" {
			return v
		}
		return match
	})
}
