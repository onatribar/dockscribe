package security

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/onatribar/dockscribe/pkg/analyzer"
	"github.com/onatribar/dockscribe/pkg/dockerignore"
	"github.com/onatribar/dockscribe/pkg/parser/dockerfile"
	"github.com/onatribar/dockscribe/pkg/secrets"
)

type Analyzer struct{}

func New() *Analyzer { return &Analyzer{} }

func (a *Analyzer) Name() string { return "security" }

func (a *Analyzer) Analyze(ctx analyzer.Context) ([]analyzer.Finding, error) {
	df, ok := ctx.File.(*dockerfile.File)
	if !ok || len(df.Instructions) == 0 {
		return nil, nil
	}

	var findings []analyzer.Finding
	findings = append(findings, checkRootUser(df)...)
	findings = append(findings, checkHealthcheck(df)...)
	findings = append(findings, checkMutableBaseImages(df)...)
	findings = append(findings, checkEOLBaseImages(df)...)
	findings = append(findings, checkStatefulRules(df)...)
	findings = append(findings, checkCrossLayerPersistence(df)...)
	findings = append(findings, checkCrossStageSecretLeak(df)...)
	findings = append(findings, checkDockerignore(df, ctx)...)
	findings = append(findings, checkDuplicateStartupInstructions(df)...)
	findings = append(findings, checkShellFormStartup(df)...)
	findings = append(findings, checkStartsCorrectly(df)...)
	findings = append(findings, checkMaintainerDeprecated(df)...)
	return findings, nil
}

func checkStatefulRules(df *dockerfile.File) []analyzer.Finding {
	var findings []analyzer.Finding
	currentUser := "root"
	secretArgs := map[string]bool{} // name -> declared as looking secret-like, in the current stage

	for _, instr := range df.Instructions {
		switch instr.Cmd {
		case "FROM":
			currentUser = "root"
			secretArgs = map[string]bool{}
		case "USER":
			currentUser = instr.Args
		case "ADD":
			findings = append(findings, checkAddURL(instr)...)
			findings = append(findings, checkChown(instr, currentUser, "ADD")...)
			findings = append(findings, checkSensitiveFileCopy(instr)...)
		case "COPY":
			findings = append(findings, checkChown(instr, currentUser, "COPY")...)
			findings = append(findings, checkSensitiveFileCopy(instr)...)
		case "ARG":
			name := instructionVarNames(instr)
			for _, n := range name {
				secretArgs[n] = secrets.LooksLikeSecretName(n)
			}
			findings = append(findings, checkSecretValues(instr)...)
		case "ENV":
			findings = append(findings, checkSecretValues(instr)...)
			findings = append(findings, checkArgPromotedToEnv(instr, secretArgs)...)
		case "RUN":
			findings = append(findings, checkRunInstruction(instr, secretArgs)...)
		case "EXPOSE":
			findings = append(findings, checkSensitivePort(instr)...)
		}
	}
	return findings
}

// S022: Dockerfile must start with FROM or ARG
// Docker refuses to build otherwise
func checkStartsCorrectly(df *dockerfile.File) []analyzer.Finding {
	if len(df.Instructions) == 0 {
		return nil
	}
	first := df.Instructions[0]
	if first.Cmd == "FROM" || first.Cmd == "ARG" {
		return nil
	}
	return []analyzer.Finding{{
		Line:     first.Line,
		Severity: analyzer.Error,
		Category: analyzer.CategorySecurity,
		RuleID:   "S022",
		Message:  fmt.Sprintf("Dockerfile starts with %s instead of FROM (or ARG before FROM).", first.Cmd),
		Detail:   "Docker requires the first instruction to be FROM, optionally preceded by ARG. This file will fail to build, and every other finding in this report may be unreliable since instructions before a FROM aren't attributed to any build stage.",
	}}
}

// S001: running as root

func checkRootUser(df *dockerfile.File) []analyzer.Finding {
	if len(df.Stages) == 0 {
		return nil
	}
	if !dockerfile.IsRootUser(df.FinalStageUser()) {
		return nil
	}

	finalStage := len(df.Stages) - 1
	lastLine := df.Stages[finalStage].StartLine
	for _, instr := range df.Instructions {
		if instr.Stage == finalStage {
			lastLine = instr.Line
		}
	}
	return []analyzer.Finding{{
		Line:     lastLine,
		Severity: analyzer.Error,
		Category: analyzer.CategorySecurity,
		RuleID:   "S001",
		Message:  "Container runs as root - no non-root USER instruction found in the final stage.",
		Detail:   "Add a USER instruction (e.g. `USER app`) before CMD/ENTRYPOINT so the container does not run as root at runtime.",
	}}
}

// S007: no HEALTHCHECK

func checkHealthcheck(df *dockerfile.File) []analyzer.Finding {
	if len(df.Stages) == 0 {
		return nil
	}
	finalStage := len(df.Stages) - 1
	lastLine := df.Stages[finalStage].StartLine

	for _, instr := range df.Instructions {
		if instr.Stage != finalStage {
			continue
		}
		if instr.Cmd == "HEALTHCHECK" {
			return nil
		}
		lastLine = instr.Line
	}
	return []analyzer.Finding{{
		Line:     lastLine,
		Severity: analyzer.Info,
		Category: analyzer.CategorySecurity,
		RuleID:   "S007",
		Message:  "No HEALTHCHECK defined.",
		Detail:   "Add a HEALTHCHECK instruction so orchestrators can detect and route around an unhealthy container.",
	}}
}

// S020/S025: multiple CMD/ENTRYPOINT/HEALTHCHECK in the same stage

var duplicateInstructionRules = map[string]string{
	"CMD": "S020", "ENTRYPOINT": "S020", "HEALTHCHECK": "S025",
}

func checkDuplicateStartupInstructions(df *dockerfile.File) []analyzer.Finding {
	var findings []analyzer.Finding
	lastLine := map[string]int{} // instruction keyword -> line of the most recent one sen per stage reset
	curStage := -1

	for _, instr := range df.Instructions {
		if instr.Stage != curStage {
			curStage = instr.Stage
			lastLine = map[string]int{}
		}
		ruleID, tracked := duplicateInstructionRules[instr.Cmd]
		if !tracked {
			continue
		}
		if prev, ok := lastLine[instr.Cmd]; ok {
			findings = append(findings, analyzer.Finding{
				Line:     instr.Line,
				Severity: analyzer.Warning,
				Category: analyzer.CategorySecurity,
				RuleID:   ruleID,
				Message:  fmt.Sprintf("%s silently overrides an earlier %s on line %d.", instr.Cmd, instr.Cmd, prev),
				Detail:   fmt.Sprintf("Only the last %s in a stage takes effect - Docker does not warn about this. Remove the earlier one, or confirm this override is intentional.", instr.Cmd),
			})
		}
		lastLine[instr.Cmd] = instr.Line
	}
	return findings
}

// S021: shell-form CMD/ENTRYPOINT

func checkShellFormStartup(df *dockerfile.File) []analyzer.Finding {
	if len(df.Stages) == 0 {
		return nil
	}
	finalStage := len(df.Stages) - 1

	var findings []analyzer.Finding
	for _, instr := range df.Instructions {
		if instr.Stage != finalStage {
			continue
		}
		if instr.Cmd != "CMD" && instr.Cmd != "ENTRYPOINT" {
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(instr.Args), "[") {
			continue // exec (JSON array) form
		}
		findings = append(findings, analyzer.Finding{
			Line:     instr.Line,
			Severity: analyzer.Warning,
			Category: analyzer.CategorySecurity,
			RuleID:   "S021",
			Message:  fmt.Sprintf("%s uses shell form instead of exec (JSON array) form.", instr.Cmd),
			Detail:   "Shell form runs your process as a child of /bin/sh -c, which usually does not forward SIGTERM - `docker stop` then waits out the full timeout and SIGKILLs instead of a graceful shutdown. Use exec form: e.g. `CMD [\"node\", \"server.js\"]`.",
		})
	}
	return findings
}

// S026: MAINTAINER is deprecated

func checkMaintainerDeprecated(df *dockerfile.File) []analyzer.Finding {
	var findings []analyzer.Finding
	for _, instr := range df.Instructions {
		if instr.Cmd != "MAINTAINER" {
			continue
		}
		findings = append(findings, analyzer.Finding{
			Line:     instr.Line,
			Severity: analyzer.Info,
			Category: analyzer.CategorySecurity,
			RuleID:   "S026",
			Message:  "MAINTAINER is deprecated.",
			Detail:   "Docker deprecated MAINTAINER in favor of LABEL, e.g. `LABEL maintainer=\"you@example.com\"` - queryable image metadata rather than a dedicated instruction.",
		})
	}
	return findings
}

// S002: ADD with a remote URL

func checkAddURL(instr dockerfile.Instruction) []analyzer.Finding {
	_, positional := dockerfile.SplitFlags(instr.Args)
	sources := positional
	if len(positional) > 1 {
		sources = positional[:len(positional)-1]
	}
	for _, p := range sources {
		if dockerfile.IsURL(p) {
			return []analyzer.Finding{{
				Line:     instr.Line,
				Severity: analyzer.Warning,
				Category: analyzer.CategorySecurity,
				RuleID:   "S002",
				Message:  "ADD fetches a remote URL directly into the image.",
				Detail:   "Prefer `curl`/`wget` with an explicit checksum, or COPY a vendored file, so the fetched content can be verified.",
			}}
		}
	}
	return nil
}

// S004: COPY/ADD without --chown while running as non-root

func checkChown(instr dockerfile.Instruction, currentUser, verb string) []analyzer.Finding {
	if dockerfile.IsRootUser(currentUser) {
		return nil
	}
	flags, _ := dockerfile.SplitFlags(instr.Args)
	if _, ok := flags["--chown"]; ok {
		return nil
	}
	return []analyzer.Finding{{
		Line:     instr.Line,
		Severity: analyzer.Warning,
		Category: analyzer.CategorySecurity,
		RuleID:   "S004",
		Message:  fmt.Sprintf("%s without --chown while running as non-root user %q.", verb, currentUser),
		Detail:   fmt.Sprintf("Files land owned by root instead of %q. Add `--chown=%s` (or a matching group) so the process can actually access them.", currentUser, currentUser),
	}}
}

// S010/S023: EXPOSE checks

var sensitivePorts = map[string]string{
	"22": "SSH", "23": "Telnet", "3389": "RDP",
}

func checkSensitivePort(instr dockerfile.Instruction) []analyzer.Finding {
	var findings []analyzer.Finding
	for _, tok := range strings.Fields(instr.Args) {
		port := tok
		if i := strings.IndexByte(tok, '/'); i >= 0 {
			port = tok[:i]
		}
		if proto, ok := sensitivePorts[port]; ok {
			findings = append(findings, analyzer.Finding{
				Line:     instr.Line,
				Severity: analyzer.Warning,
				Category: analyzer.CategorySecurity,
				RuleID:   "S010",
				Message:  fmt.Sprintf("EXPOSE %s documents a %s port.", port, proto),
				Detail:   "Exposing a management/remote-access port from an application container is rarely intentional - double check this isn't a leftover from the base image or debugging.",
			})
		}
		if n, err := strconv.Atoi(port); err == nil && (n < 0 || n > 65535) {
			findings = append(findings, analyzer.Finding{
				Line:     instr.Line,
				Severity: analyzer.Warning,
				Category: analyzer.CategorySecurity,
				RuleID:   "S023",
				Message:  fmt.Sprintf("EXPOSE %s is not a valid port number.", port),
				Detail:   "Valid TCP/UDP ports are 0-65535 - this is almost certainly a typo, and the build will fail.",
			})
		}
	}
	return findings
}

// S019: broad COPY with no (or insufficient) .dockerignore

var dockerignoreSecretPaths = []string{".git", ".env", "id_rsa", ".pem", ".ssh", ".aws"}

func checkDockerignore(df *dockerfile.File, ctx analyzer.Context) []analyzer.Finding {
	if !df.HasBroadCopy() {
		return nil
	}

	content, ok := ctx.ReadSibling(".dockerignore")
	if !ok {
		return []analyzer.Finding{{
			Line:     1,
			Severity: analyzer.Warning,
			Category: analyzer.CategorySecurity,
			RuleID:   "S019",
			Message:  "Broad COPY with no .dockerignore file.",
			Detail:   "Without a .dockerignore, `COPY . .` sends everything in the build context to the daemon and into the image - including .git history, .env files, and credentials that happen to sit in the project directory. Add one that excludes at least .git, .env, and any local credential files.",
		}}
	}

	patterns := dockerignore.Parse(content)
	var missing []string
	for _, p := range dockerignoreSecretPaths {
		if !dockerignore.Excludes(patterns, p) {
			missing = append(missing, p)
		}
	}
	if len(missing) == 0 {
		return nil
	}
	return []analyzer.Finding{{
		Line:     1,
		Severity: analyzer.Warning,
		Category: analyzer.CategorySecurity,
		RuleID:   "S019",
		Message:  fmt.Sprintf(".dockerignore doesn't exclude: %s.", strings.Join(missing, ", ")),
		Detail:   "A broad COPY sends anything not excluded to the build context, including these commonly-sensitive paths if they exist in the project directory.",
	}}
}
