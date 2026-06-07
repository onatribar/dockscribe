package explain

import (
	"fmt"
	"strings"

	"github.com/onatribar/dockscribe/pkg/analyzer"
	"github.com/onatribar/dockscribe/pkg/parser"
	"github.com/onatribar/dockscribe/pkg/parser/dockerfile"
)

type Analyzer struct{}

func New() *Analyzer { return &Analyzer{} }

func (a *Analyzer) Name() string { return "explanation" }

func (a *Analyzer) Analyze(f parser.ParsedFile) ([]analyzer.Finding, error) {
	df, ok := f.(*dockerfile.File)
	if !ok {
		return nil, nil
	}

	var findings []analyzer.Finding
	for _, instr := range df.Instructions {
		msg, ok := explain(instr, df)
		if !ok {
			continue
		}
		findings = append(findings, analyzer.Finding{
			Line:     instr.Line,
			Severity: analyzer.Info,
			Category: analyzer.CategoryExplanation,
			Message:  msg,
		})
	}
	return findings, nil
}

func explain(instr dockerfile.Instruction, df *dockerfile.File) (string, bool) {
	switch instr.Cmd {
	case "FROM":
		return explainFrom(instr, df), true
	case "WORKDIR":
		return fmt.Sprintf("Sets %q as the working directory for subsequent instructions.", instr.Args), true
	case "COPY":
		return explainCopyAdd("Copies", instr.Args, false), true
	case "ADD":
		return explainCopyAdd("Adds", instr.Args, true), true
	case "RUN":
		return fmt.Sprintf("Runs: %s", instr.Args), true
	case "ENV":
		return explainEnv(instr.Args), true
	case "ARG":
		return explainArg(instr.Args), true
	case "EXPOSE":
		return fmt.Sprintf("Documents that the container listens on port(s) %s (does not publish them).", instr.Args), true
	case "CMD":
		return fmt.Sprintf("Default startup command: %s.", instr.Args), true
	case "ENTRYPOINT":
		return fmt.Sprintf("Configures the container's entrypoint: %s.", instr.Args), true
	case "USER":
		return fmt.Sprintf("Switches to user %q for subsequent instructions.", instr.Args), true
	case "LABEL":
		return fmt.Sprintf("Attaches image metadata: %s.", instr.Args), true
	case "VOLUME":
		return fmt.Sprintf("Declares mount point(s): %s.", instr.Args), true
	case "HEALTHCHECK":
		return fmt.Sprintf("Defines a container health check: %s.", instr.Args), true
	case "SHELL":
		return fmt.Sprintf("Changes the default shell for RUN/CMD/ENTRYPOINT to %s.", instr.Args), true
	case "ONBUILD":
		return fmt.Sprintf("Registers a trigger instruction for child builds: %s.", instr.Args), true
	case "STOPSIGNAL":
		return fmt.Sprintf("Sets the stop signal sent to the container to %s.", instr.Args), true
	default:
		return "", false
	}
}

func explainFrom(instr dockerfile.Instruction, df *dockerfile.File) string {
	for i := range df.Stages {
		stage := df.Stages[i]
		if stage.StartLine != instr.Line {
			continue
		}
		if stage.Name != "" {
			return fmt.Sprintf("Base image: %s - starts build stage %d, named %q.", stage.BaseImage, stage.Index, stage.Name)
		}
		return fmt.Sprintf("Base image: %s - starts build stage %d.", stage.BaseImage, stage.Index)
	}
	return fmt.Sprintf("Base image: %s.", instr.Args)
}

// describes a COPY or ADD instruction in terms of its
// sources, destination, and any --from stage reference
func explainCopyAdd(verb, args string, isAdd bool) string {
	flags, positional := splitFlags(args)
	if len(positional) == 0 {
		return fmt.Sprintf("%s files into the image.", verb)
	}

	dest := positional[len(positional)-1]
	sources := positional[:len(positional)-1]

	var b strings.Builder
	b.WriteString(verb)
	b.WriteByte(' ')
	if len(sources) == 0 {
		b.WriteString("files")
	} else {
		b.WriteString(strings.Join(sources, ", "))
	}
	b.WriteString(" into the image at ")
	b.WriteString(dest)
	if from, ok := flags["--from"]; ok {
		fmt.Fprintf(&b, " (from build stage %q)", from)
	}
	b.WriteByte('.')
	if isAdd {
		b.WriteString(" ADD also auto-extracts local archives and can fetch remote URLs.")
	}
	return b.String()
}

func explainEnv(args string) string {
	fields := strings.Fields(args)
	if len(fields) == 0 {
		return "Sets an environment variable."
	}
	if i := strings.IndexByte(fields[0], '='); i >= 0 {
		return fmt.Sprintf("Sets environment variable %s to %q.", fields[0][:i], fields[0][i+1:])
	}
	if len(fields) >= 2 {
		return fmt.Sprintf("Sets environment variable %s to %q.", fields[0], strings.Join(fields[1:], " "))
	}
	return fmt.Sprintf("Declares environment variable %s.", fields[0])
}

func explainArg(args string) string {
	if i := strings.IndexByte(args, '='); i >= 0 {
		return fmt.Sprintf("Declares build argument %s with default %q.", args[:i], args[i+1:])
	}
	return fmt.Sprintf("Declares build argument %s (no default).", args)
}

// separates leading "--flag" or "--flag=value" tokens from positional arguments.
func splitFlags(args string) (flags map[string]string, positional []string) {
	flags = map[string]string{}
	for _, field := range strings.Fields(args) {
		if !strings.HasPrefix(field, "--") {
			positional = append(positional, field)
			continue
		}
		if i := strings.IndexByte(field, '='); i >= 0 {
			flags[field[:i]] = field[i+1:]
		} else {
			flags[field] = ""
		}
	}
	return flags, positional
}
