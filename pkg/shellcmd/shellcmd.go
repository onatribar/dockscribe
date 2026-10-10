package shellcmd

import (
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// Command is a single simple command (a "call") found anywhere in a parsed script
// e.g. "curl -fsSL https://x" -> Name: "curl", Args: ["-fsSL", "https://x"].
type Command struct {
	Name    string
	Args    []string
	Assigns map[string]string // leading VAR=value assignments attached to this call, e.g. "CGO_ENABLED=0 go build"
}

// For substring/regex checks against the raw command.
func (c Command) FullArgs() []string {
	return append([]string{c.Name}, c.Args...)
}

func (c Command) Joined() string {
	return strings.Join(c.FullArgs(), " ")
}

// PipePair is one adjacent From|To relationship; a three-stage pipeline
// `a | b | c` yields two pairs: (a,b) and (b,c).
type PipePair struct {
	From Command
	To   Command
}

// Flattened, best-effort structural summary of a shell script
type Analysis struct {
	Commands  []Command  // every simple command in order
	PipePairs []PipePair // every adjacent pipe relationship
	VarRefs   []string   // every distinct variable name referenced via $VAR / ${VAR} (in first seen order)
	Writes    []string   // every file path the script writes to (redirects, and cp/mv/install/tee destinations) but deduplicated
}

// A write to "/root/.ssh/id_rsa" counts as writing under "/root/.ssh".
func (a Analysis) WritesTo(target string) bool {
	target = strings.TrimSuffix(target, "/")
	for _, w := range a.Writes {
		if w == target || strings.HasPrefix(w, target+"/") {
			return true
		}
	}
	return false
}

var removeCommandNames = map[string]bool{"rm": true, "shred": true, "unlink": true}

// Matches path exactly (rm /abc/def/ghi) or via an ancestor directory
// (rm -rf /abc).
func (a Analysis) RemovesPath(path string) bool {
	path = strings.TrimSuffix(path, "/")
	for _, c := range a.Commands {
		if !removeCommandNames[c.Name] {
			continue
		}
		for _, arg := range c.Args {
			if strings.HasPrefix(arg, "-") {
				continue
			}
			arg = normalizeRemoveArg(arg)
			if arg == path || strings.HasPrefix(path, arg+"/") {
				return true
			}
		}
	}
	return false
}

// So `rm -rf /var/lib/apt/lists/*` is recognized as targeting the same
// path as `rm -rf /var/lib/apt/lists`.
func normalizeRemoveArg(arg string) string {
	arg = strings.TrimSuffix(arg, "/*")
	arg = strings.TrimSuffix(arg, "*")
	return strings.TrimSuffix(arg, "/")
}

func (a Analysis) HasCommand(name string) bool {
	for _, c := range a.Commands {
		if c.Name == name {
			return true
		}
	}
	return false
}

// Covers both $NAME and ${NAME} parameter-expansion forms.
func (a Analysis) RefersTo(name string) bool {
	for _, v := range a.VarRefs {
		if v == name {
			return true
		}
	}
	return false
}

// ok is false if script isn't parseable as a shell script (exotic
// syntax, JSON-array exec form); callers fall back to treating it as
// opaque text.
func Analyze(script string) (Analysis, bool) {
	if strings.TrimSpace(script) == "" {
		return Analysis{}, false
	}

	parser := syntax.NewParser(syntax.Variant(syntax.LangBash), syntax.KeepComments(false))
	f, err := parser.Parse(strings.NewReader(script), "")
	if err != nil {
		return Analysis{}, false
	}

	var a Analysis
	seenVars := map[string]bool{}
	seenWrites := map[string]bool{}
	addWrite := func(path string) {
		path = strings.TrimSuffix(path, "/")
		if path == "" || seenWrites[path] {
			return
		}
		seenWrites[path] = true
		a.Writes = append(a.Writes, path)
	}

	syntax.Walk(f, func(node syntax.Node) bool {
		switch n := node.(type) {
		case *syntax.CallExpr:
			if cmd, ok := commandFromCall(n); ok {
				a.Commands = append(a.Commands, cmd)
				for _, target := range writeTargets(cmd) {
					addWrite(target)
				}
			}
		case *syntax.BinaryCmd:
			if n.Op == syntax.Pipe || n.Op == syntax.PipeAll {
				from, fromOK := lastCommand(n.X)
				to, toOK := firstCommand(n.Y)
				if fromOK && toOK {
					a.PipePairs = append(a.PipePairs, PipePair{From: from, To: to})
				}
			}
		case *syntax.ParamExp:
			if n.Param != nil && n.Param.Value != "" && !seenVars[n.Param.Value] {
				seenVars[n.Param.Value] = true
				a.VarRefs = append(a.VarRefs, n.Param.Value)
			}
		case *syntax.Stmt:
			for _, r := range n.Redirs {
				if isWriteRedirect(r.Op) && r.Word != nil {
					addWrite(wordText(r.Word))
				}
			}
		}
		return true
	})

	return a, true
}

// As opposed to reading, duplicating a descriptor, or a here-document.
func isWriteRedirect(op syntax.RedirOperator) bool {
	switch op {
	case syntax.RdrOut, syntax.AppOut, syntax.RdrClob, syntax.RdrAll, syntax.RdrAllClob, syntax.AppAll, syntax.AppAllClob:
		return true
	}
	return false
}

// See writeTargets for how each one's write target is actually resolved.
var writeCommandNames = map[string]bool{"cp": true, "mv": true, "install": true, "tee": true}

// Beyond any redirect (handled separately) - e.g. the destination
// argument of cp/mv/install, or tee's output file arguments.
func writeTargets(cmd Command) []string {
	if !writeCommandNames[cmd.Name] {
		return nil
	}
	var args []string
	for _, a := range cmd.Args {
		if !strings.HasPrefix(a, "-") {
			args = append(args, a)
		}
	}
	if len(args) == 0 {
		return nil
	}
	if cmd.Name == "tee" {
		// tee writes to every non-flag argument (in addition to stdout).
		return args
	}
	// cp/mv/install: `SRC... DST` - the destination is the last argument.
	return args[len(args)-1:]
}

func commandFromCall(n *syntax.CallExpr) (Command, bool) {
	assigns := map[string]string{}
	for _, as := range n.Assigns {
		if as.Name == nil {
			continue
		}
		val := ""
		if as.Value != nil {
			val = wordText(as.Value)
		}
		assigns[as.Name.Value] = val
	}
	if len(n.Args) == 0 {
		// A bare assignment statement (e.g. `ENV_VAR=x`), not a call.
		return Command{Assigns: assigns}, len(assigns) > 0
	}
	words := make([]string, 0, len(n.Args))
	for _, w := range n.Args {
		words = append(words, wordText(w))
	}
	return Command{Name: words[0], Args: words[1:], Assigns: assigns}, true
}

// For `a | b | c`, parsed as nested pipe (a|b) | c, the last command of
// the X side is `b`.
func lastCommand(s *syntax.Stmt) (Command, bool) {
	if s == nil {
		return Command{}, false
	}
	switch cmd := s.Cmd.(type) {
	case *syntax.CallExpr:
		return commandFromCall(cmd)
	case *syntax.BinaryCmd:
		if cmd.Op == syntax.Pipe || cmd.Op == syntax.PipeAll {
			return lastCommand(cmd.Y)
		}
	}
	return Command{}, false
}

func firstCommand(s *syntax.Stmt) (Command, bool) {
	if s == nil {
		return Command{}, false
	}
	switch cmd := s.Cmd.(type) {
	case *syntax.CallExpr:
		return commandFromCall(cmd)
	case *syntax.BinaryCmd:
		if cmd.Op == syntax.Pipe || cmd.Op == syntax.PipeAll {
			return firstCommand(cmd.X)
		}
	}
	return Command{}, false
}

// Dynamic parts (expansions, substitutions) render as their shell syntax
// (e.g. "$TOKEN") without ever being expanded - literal text passes
// through verbatim.
func wordText(w *syntax.Word) string {
	if w == nil {
		return ""
	}
	var b strings.Builder
	for _, part := range w.Parts {
		b.WriteString(wordPartText(part))
	}
	return b.String()
}

func wordPartText(part syntax.WordPart) string {
	switch p := part.(type) {
	case *syntax.Lit:
		return p.Value
	case *syntax.SglQuoted:
		return p.Value
	case *syntax.DblQuoted:
		var b strings.Builder
		for _, pp := range p.Parts {
			b.WriteString(wordPartText(pp))
		}
		return b.String()
	case *syntax.ParamExp:
		if p.Param == nil {
			return ""
		}
		if p.Short {
			return "$" + p.Param.Value
		}
		return "${" + p.Param.Value + "}"
	case *syntax.CmdSubst:
		return "$(...)"
	case *syntax.ArithmExp:
		return "$((...))"
	default:
		return ""
	}
}
