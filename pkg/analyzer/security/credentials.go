package security

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/onatribar/dockscribe/pkg/analyzer"
	"github.com/onatribar/dockscribe/pkg/parser/dockerfile"
	"github.com/onatribar/dockscribe/pkg/secrets"
	"github.com/onatribar/dockscribe/pkg/shellcmd"
)

// S003/S013/S014: secret-looking ARG/ENV

// S003 is a weak check on the variable name
// S013/S014 scan the value for credential-shaped content, a stronger signal
func checkSecretValues(instr dockerfile.Instruction) []analyzer.Finding {
	var findings []analyzer.Finding
	for _, name := range instructionVarNames(instr) {
		if secrets.LooksLikeSecretName(name) {
			findings = append(findings, analyzer.Finding{
				Line:     instr.Line,
				Severity: analyzer.Warning,
				Category: analyzer.CategorySecurity,
				RuleID:   "S003",
				Message:  fmt.Sprintf("%s %q looks like it holds a secret.", instr.Cmd, name),
				Detail:   "Secrets baked into ARG/ENV are visible in the image layer history (`docker history`). Use BuildKit secret mounts or inject the value at runtime instead.",
			})
		}
	}
	values := instructionVarValues(instr)
	for _, name := range analyzer.SortedKeys(values) {
		for _, m := range secrets.ScanValue(values[name]) {
			if m.Confidence == secrets.High {
				findings = append(findings, analyzer.Finding{
					Line:     instr.Line,
					Severity: analyzer.Error,
					Category: analyzer.CategorySecurity,
					RuleID:   "S013",
					Message:  fmt.Sprintf("%s %q's value matches a known %s format.", instr.Cmd, name, m.Kind),
					Detail:   "This looks like a real credential, not a placeholder. It is permanently baked into the image's metadata/layer history. Rotate it immediately and use a build secret instead.",
				})
			} else {
				findings = append(findings, analyzer.Finding{
					Line:     instr.Line,
					Severity: analyzer.Warning,
					Category: analyzer.CategorySecurity,
					RuleID:   "S014",
					Message:  fmt.Sprintf("%s %q's value looks like a high-entropy secret.", instr.Cmd, name),
					Detail:   "This value doesn't match a known credential format, but its randomness is consistent with a real secret rather than ordinary text. Verify it isn't a leaked key.",
				})
			}
		}
	}
	return findings
}

// ENV may declare several KEY=VALUE pairs or a legacy "KEY value" pair
func instructionVarNames(instr dockerfile.Instruction) []string {
	return analyzer.SortedKeys(instructionVarValues(instr))
}

// omit ARG without a default, or ENV with an empty value
func instructionVarValues(instr dockerfile.Instruction) map[string]string {
	args := strings.TrimSpace(instr.Args)
	if args == "" {
		return nil
	}
	out := map[string]string{}

	switch instr.Cmd {
	case "ARG":
		name, value := dockerfile.ParseArgDeclaration(args)
		out[name] = value
	case "ENV":
		fields := strings.Fields(args)
		if len(fields) == 0 {
			return nil
		}
		if strings.Contains(fields[0], "=") {
			for _, f := range fields {
				if i := strings.IndexByte(f, '='); i >= 0 {
					out[f[:i]] = strings.Trim(f[i+1:], `"'`)
				}
			}
		} else if len(fields) >= 2 {
			out[fields[0]] = strings.Trim(strings.Join(fields[1:], " "), `"'`)
		} else {
			out[fields[0]] = ""
		}
	}
	return out
}

// S015: ARG promoted into ENV

func checkArgPromotedToEnv(instr dockerfile.Instruction, secretArgs map[string]bool) []analyzer.Finding {
	var findings []analyzer.Finding
	values := instructionVarValues(instr)
	for _, name := range analyzer.SortedKeys(values) {
		ref := strings.Trim(values[name], "${}")
		if !secretArgs[ref] {
			continue
		}
		findings = append(findings, analyzer.Finding{
			Line:     instr.Line,
			Severity: analyzer.Error,
			Category: analyzer.CategorySecurity,
			RuleID:   "S015",
			Message:  fmt.Sprintf("Build ARG %q is promoted into ENV %q.", ref, name),
			Detail:   "A build-time ARG is transient, but assigning it to ENV bakes the value permanently into the image's config and every container started from it - visible forever via `docker inspect`. If this is a secret, don't promote it to ENV.",
		})
	}
	return findings
}

// S016: secret ARG interpolated into a RUN command

// parse RUN command once and fan that parse out to every RUN-scoped check starting with its own
func checkRunInstruction(instr dockerfile.Instruction, secretArgs map[string]bool) []analyzer.Finding {
	var findings []analyzer.Finding
	a, ok := shellcmd.Analyze(dockerfile.StripLeadingRunFlags(instr.Args))
	if !ok {
		return nil
	}

	for _, name := range analyzer.SortedKeys(secretArgs) {
		if !secretArgs[name] || !a.RefersTo(name) {
			continue
		}
		findings = append(findings, analyzer.Finding{
			Line:     instr.Line,
			Severity: analyzer.Error,
			Category: analyzer.CategorySecurity,
			RuleID:   "S016",
			Message:  fmt.Sprintf("Build ARG %q is used inside a RUN command.", name),
			Detail:   "Even though ARG values aren't stored in the final image config, they end up in this layer's build history/cache and are recoverable via `docker history --no-trunc`. Use `RUN --mount=type=secret` instead of ARG for anything sensitive.",
		})
	}

	findings = append(findings, checkCurlPipeShell(a, instr)...)
	findings = append(findings, checkSudo(a, instr)...)
	findings = append(findings, checkInsecureTLS(a, instr)...)
	findings = append(findings, checkUnpinnedPackageInstall(a, instr)...)
	return findings
}

// S009: sensitive files copied into the image

var sensitiveFilePatterns = []string{
	"id_rsa", "id_dsa", "id_ecdsa", "id_ed25519", ".pem", ".key", ".pfx", ".p12",
	".env", "credentials.json", ".netrc", ".npmrc", ".pgpass", ".git/",
	".aws/credentials", ".ssh/", "known_hosts",
}

func matchesSensitivePattern(s string) bool {
	lower := strings.ToLower(s)
	for _, pat := range sensitiveFilePatterns {
		if strings.Contains(lower, pat) {
			return true
		}
	}
	return false
}

func checkSensitiveFileCopy(instr dockerfile.Instruction) []analyzer.Finding {
	_, positional := dockerfile.SplitFlags(instr.Args)
	if len(positional) < 1 {
		return nil
	}
	sources := positional
	if len(positional) > 1 {
		sources = positional[:len(positional)-1]
	}
	for _, src := range sources {
		if matchesSensitivePattern(src) {
			return []analyzer.Finding{{
				Line:     instr.Line,
				Severity: analyzer.Warning,
				Category: analyzer.CategorySecurity,
				RuleID:   "S009",
				Message:  fmt.Sprintf("Copies a potentially sensitive file (%s) into the image.", src),
				Detail:   "Credentials, private keys, and .git history baked into a layer are recoverable by anyone with access to it, even if a later layer removes them. Use build secrets or a .dockerignore entry instead.",
			}}
		}
	}
	return nil
}

// S017: file written/copied in one layer, removed in a later one
// S024: sensitive file survives into a later stage via COPY --from

type sensitiveIntroduction struct {
	path string
	line int
}

// Sensitive-looking file paths introduced in one stage (via COPY/ADD or a writing RUN)
// plus each RUN's shell analysis for callers to check removals without re-parsing
// Shared by S017 and S024
func collectStageIntroductions(df *dockerfile.File, stageIdx int) (introduced []sensitiveIntroduction, runs []shellcmd.Analysis) {
	for _, instr := range df.Instructions {
		if instr.Stage != stageIdx {
			continue
		}
		switch instr.Cmd {
		case "COPY", "ADD":
			_, positional := dockerfile.SplitFlags(instr.Args)
			if len(positional) < 2 {
				continue
			}
			dest := positional[len(positional)-1]
			sources := positional[:len(positional)-1]
			for _, src := range sources {
				if matchesSensitivePattern(src) {
					introduced = append(introduced, sensitiveIntroduction{path: dest, line: instr.Line})
					break
				}
			}
		case "RUN":
			a, ok := shellcmd.Analyze(dockerfile.StripLeadingRunFlags(instr.Args))
			if !ok {
				continue
			}
			runs = append(runs, a)
			for _, w := range a.Writes {
				if matchesSensitivePattern(w) {
					introduced = append(introduced, sensitiveIntroduction{path: w, line: instr.Line})
				}
			}
		}
	}
	return introduced, runs
}

// only the stage's final filesystem state matters, since that's what a later "COPY --from" would see.
func stillPresentAtStageEnd(introduced []sensitiveIntroduction, runs []shellcmd.Analysis) []sensitiveIntroduction {
	var present []sensitiveIntroduction
	for _, intro := range introduced {
		removed := false
		for _, a := range runs {
			if a.RemovesPath(intro.path) {
				removed = true
				break
			}
		}
		if !removed {
			present = append(present, intro)
		}
	}
	return present
}

// Docker commits a layer per instruction
// a file introduced in one instruction and removed in a later, different one still exists in the earlier layer
func checkCrossLayerPersistence(df *dockerfile.File) []analyzer.Finding {
	var findings []analyzer.Finding
	numStages := len(df.Stages)
	if numStages == 0 {
		numStages = 1
	}

	for stageIdx := 0; stageIdx < numStages; stageIdx++ {
		introduced, _ := collectStageIntroductions(df, stageIdx)
		reported := map[string]bool{}

		for _, instr := range df.Instructions {
			if instr.Stage != stageIdx || instr.Cmd != "RUN" {
				continue
			}
			a, ok := shellcmd.Analyze(dockerfile.StripLeadingRunFlags(instr.Args))
			if !ok {
				continue
			}
			for _, intro := range introduced {
				if intro.line >= instr.Line || reported[intro.path] {
					continue
				}
				if a.RemovesPath(intro.path) {
					reported[intro.path] = true
					findings = append(findings, analyzer.Finding{
						Line:     intro.line,
						Severity: analyzer.Error,
						Category: analyzer.CategorySecurity,
						RuleID:   "S017",
						Message:  fmt.Sprintf("%q is removed later (L%d) but was already written in an earlier layer (L%d).", intro.path, instr.Line, intro.line),
						Detail:   "Files written in one instruction and removed in a different, later one still exist in the earlier image layer and are recoverable from a saved/exported image. Remove the file in the SAME instruction that created it, or avoid writing it to disk at all (use a build secret mount).",
					})
				}
			}
		}
	}
	return findings
}

// COPY --from copies the source stage's current filesystem, not its layer history
func checkCrossStageSecretLeak(df *dockerfile.File) []analyzer.Finding {
	if len(df.Stages) < 2 {
		return nil
	}

	stillPresent := make([][]sensitiveIntroduction, len(df.Stages))
	for i := range df.Stages {
		introduced, runs := collectStageIntroductions(df, i)
		stillPresent[i] = stillPresentAtStageEnd(introduced, runs)
	}

	var findings []analyzer.Finding
	for _, instr := range df.Instructions {
		if instr.Cmd != "COPY" {
			continue
		}
		flags, positional := dockerfile.SplitFlags(instr.Args)
		from, ok := flags["--from"]
		if !ok || len(positional) < 2 {
			continue
		}
		srcStage, ok := resolveFromStage(df, from)
		if !ok || srcStage >= instr.Stage {
			continue
		}
		sources := positional[:len(positional)-1]
		for _, intro := range stillPresent[srcStage] {
			for _, src := range sources {
				if !copySourceMatchesPath(src, intro.path) {
					continue
				}
				findings = append(findings, analyzer.Finding{
					Line:     instr.Line,
					Severity: analyzer.Error,
					Category: analyzer.CategorySecurity,
					RuleID:   "S024",
					Message:  fmt.Sprintf("Copies %q from stage %d, which still contains %q (written on L%d).", src, srcStage, intro.path, intro.line),
					Detail:   "COPY --from pulls in the source stage's current filesystem content, not its layer history - discarding that stage's own layers doesn't help if the file it never cleaned up gets copied into this one anyway. Remove the file before the source stage ends, or don't write it there at all.",
				})
			}
		}
	}
	return findings
}

// ok is false for anything else, like an external image reference
func resolveFromStage(df *dockerfile.File, from string) (int, bool) {
	if idx, err := strconv.Atoi(from); err == nil {
		if idx >= 0 && idx < len(df.Stages) {
			return idx, true
		}
		return 0, false
	}
	for i, s := range df.Stages {
		if s.Name == from {
			return i, true
		}
	}
	return 0, false
}

// matches an exact path, a broad copy of the whole stage (".", "/", or empty), or copySrc naming a directory that contains sensitivePath
func copySourceMatchesPath(copySrc, sensitivePath string) bool {
	copySrc = strings.TrimSuffix(copySrc, "/")
	sensitivePath = strings.TrimSuffix(sensitivePath, "/")
	if copySrc == "." || copySrc == "" || copySrc == "/" {
		return true
	}
	if copySrc == sensitivePath {
		return true
	}
	return strings.HasPrefix(sensitivePath, copySrc+"/")
}
