package performance

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/onatribar/dockscribe/pkg/analyzer"
	"github.com/onatribar/dockscribe/pkg/imageref"
	"github.com/onatribar/dockscribe/pkg/parser/dockerfile"
	"github.com/onatribar/dockscribe/pkg/shellcmd"
)

type Analyzer struct{}

func New() *Analyzer { return &Analyzer{} }

func (a *Analyzer) Name() string { return "performance" }

func (a *Analyzer) Analyze(ctx analyzer.Context) ([]analyzer.Finding, error) {
	df, ok := ctx.File.(*dockerfile.File)
	if !ok || len(df.Instructions) == 0 {
		return nil, nil
	}

	var findings []analyzer.Finding
	findings = append(findings, checkMultiStage(df)...)
	findings = append(findings, checkFinalBaseImage(df)...)
	findings = append(findings, checkConsecutiveRun(df)...)
	findings = append(findings, checkEarlyBroadCopy(df)...)
	findings = append(findings, checkDeadStage(df)...)
	findings = append(findings, checkDanglingCopyFrom(df)...)
	findings = append(findings, checkSelfReferentialCopyFrom(df)...)
	findings = append(findings, checkFullStageCopy(df)...)
	findings = append(findings, checkDuplicateStageNames(df)...)
	findings = append(findings, checkHardcodedPlatform(df)...)
	findings = append(findings, checkDockerignore(df, ctx)...)
	findings = append(findings, checkMissingCopySource(df, ctx)...)

	pipefailSet := map[int]bool{} // stage index -> SHELL with -o pipefail seen so far
	for _, instr := range df.Instructions {
		switch instr.Cmd {
		case "SHELL":
			if strings.Contains(instr.Args, "pipefail") {
				pipefailSet[instr.Stage] = true
			}
		case "RUN":
			findings = append(findings, checkRunInstruction(instr, pipefailSet[instr.Stage])...)
		case "ADD":
			findings = append(findings, checkAddVsCopy(instr)...)
		case "COPY":
			findings = append(findings, checkHeavyDirCopy(instr)...)
		case "WORKDIR":
			findings = append(findings, checkRelativeWorkdir(instr)...)
		}
	}
	return findings, nil
}

func checkRunInstruction(instr dockerfile.Instruction, pipefailSet bool) []analyzer.Finding {
	a, ok := shellcmd.Analyze(dockerfile.StripLeadingRunFlags(instr.Args))
	if !ok {
		return nil
	}
	var findings []analyzer.Finding
	findings = append(findings, checkPackageCacheCleanup(a, instr)...)
	findings = append(findings, checkNoInstallRecommends(a, instr)...)
	findings = append(findings, checkAptUpdateAlone(a, instr)...)
	findings = append(findings, checkMissingPipefail(a, instr, pipefailSet)...)
	return findings
}

// P005: no multi-stage build
func checkMultiStage(df *dockerfile.File) []analyzer.Finding {
	if len(df.Stages) > 1 {
		return nil
	}
	line := 1
	if len(df.Stages) == 1 {
		line = df.Stages[0].StartLine
	}
	return []analyzer.Finding{{
		Line:     line,
		Severity: analyzer.Info,
		Category: analyzer.CategoryPerformance,
		RuleID:   "P005",
		Message:  "No multi-stage build detected.",
		Detail:   "Build tooling and intermediate artifacts stay in the final image. Split into a `builder` stage and COPY only the built output into a slim final stage.",
	}}
}

// P010: dead build stage. never consumed by a later COPY --from and not the final stage, pure wasted build compute.
func checkDeadStage(df *dockerfile.File) []analyzer.Finding {
	if len(df.Stages) < 2 {
		return nil
	}

	referenced := map[string]bool{}
	for _, instr := range df.Instructions {
		if instr.Cmd != "COPY" {
			continue
		}
		flags, _ := dockerfile.SplitFlags(instr.Args)
		if from, ok := flags["--from"]; ok {
			referenced[from] = true
		}
	}

	var findings []analyzer.Finding
	finalIdx := len(df.Stages) - 1
	for i, stage := range df.Stages {
		if i == finalIdx {
			continue
		}
		used := referenced[strconv.Itoa(i)] || (stage.Name != "" && referenced[stage.Name])
		if used {
			continue
		}
		label := fmt.Sprintf("stage %d", i)
		if stage.Name != "" {
			label = fmt.Sprintf("stage %d (%q)", i, stage.Name)
		}
		findings = append(findings, analyzer.Finding{
			Line:     stage.StartLine,
			Severity: analyzer.Warning,
			Category: analyzer.CategoryPerformance,
			RuleID:   "P010",
			Message:  fmt.Sprintf("Build %s is never used by a later COPY --from and isn't the final stage.", label),
			Detail:   "Nothing in the shipped image depends on this stage, so building it is pure wasted compute. Remove it, or reference it with COPY --from if it was meant to contribute to a later stage.",
		})
	}
	return findings
}

// P012: dangling numeric COPY --from index.
// narrow to a numeric, out-of-range index on purpose
// --from can also name an external image, indistinguishable from a typo'd stage name, but a bare integer can only mean a stage index
func checkDanglingCopyFrom(df *dockerfile.File) []analyzer.Finding {
	var findings []analyzer.Finding
	for _, instr := range df.Instructions {
		if instr.Cmd != "COPY" {
			continue
		}
		flags, _ := dockerfile.SplitFlags(instr.Args)
		from, ok := flags["--from"]
		if !ok {
			continue
		}
		idx, err := strconv.Atoi(from)
		if err != nil {
			continue // not numeric, could be a stage name or external image, not a concern here
		}
		if idx < 0 || idx >= len(df.Stages) || idx >= instr.Stage {
			findings = append(findings, analyzer.Finding{
				Line:     instr.Line,
				Severity: analyzer.Warning,
				Category: analyzer.CategoryPerformance,
				RuleID:   "P012",
				Message:  fmt.Sprintf("COPY --from=%d references a stage index that doesn't exist yet at this point.", idx),
				Detail:   "A numeric --from can only mean a build stage index. This one is out of range (or refers to the current/a later stage), which will fail the build - likely a stale reference after stages were added, removed, or reordered.",
			})
		}
	}
	return findings
}

// P018: COPY --from references its own stage
// a stage can only be copied from once it's finished building
func checkSelfReferentialCopyFrom(df *dockerfile.File) []analyzer.Finding {
	var findings []analyzer.Finding
	for _, instr := range df.Instructions {
		if instr.Cmd != "COPY" || instr.Stage < 0 || instr.Stage >= len(df.Stages) {
			continue
		}
		flags, _ := dockerfile.SplitFlags(instr.Args)
		from, ok := flags["--from"]
		currentName := df.Stages[instr.Stage].Name
		if !ok || currentName == "" || from != currentName {
			continue
		}
		findings = append(findings, analyzer.Finding{
			Line:     instr.Line,
			Severity: analyzer.Error,
			Category: analyzer.CategoryPerformance,
			RuleID:   "P018",
			Message:  fmt.Sprintf("COPY --from=%q references its own stage.", from),
			Detail:   "A stage can't copy from itself - it hasn't finished building yet at this point in its own instructions. This is either a stale reference after stages were renamed, or was meant to reference a different, earlier stage.",
		})
	}
	return findings
}

// P019: COPY --from copies an entire stage's filesystem, defeating the point of splitting it out as its own stage
func checkFullStageCopy(df *dockerfile.File) []analyzer.Finding {
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
		for _, src := range positional[:len(positional)-1] {
			if !dockerfile.IsBroadCopySource(src) {
				continue
			}
			findings = append(findings, analyzer.Finding{
				Line:     instr.Line,
				Severity: analyzer.Warning,
				Category: analyzer.CategoryPerformance,
				RuleID:   "P019",
				Message:  fmt.Sprintf("COPY --from=%s copies the entire stage's filesystem.", from),
				Detail:   "This defeats the point of a multi-stage build. Copy only the specific built artifact(s) this stage actually needs (e.g. `/out/app`), not everything the build stage happens to contain.",
			})
			break
		}
	}
	return findings
}

// P013: duplicate build stage names
func checkDuplicateStageNames(df *dockerfile.File) []analyzer.Finding {
	var findings []analyzer.Finding
	seen := map[string]int{} // name -> line of first stage using it
	for _, stage := range df.Stages {
		if stage.Name == "" {
			continue
		}
		if firstLine, ok := seen[stage.Name]; ok {
			findings = append(findings, analyzer.Finding{
				Line:     stage.StartLine,
				Severity: analyzer.Warning,
				Category: analyzer.CategoryPerformance,
				RuleID:   "P013",
				Message:  fmt.Sprintf("Stage name %q was already used on line %d.", stage.Name, firstLine),
				Detail:   "A later COPY --from referencing this name will resolve to whichever stage Docker considers the match, not necessarily the one you mean - rename one of the stages.",
			})
			continue
		}
		seen[stage.Name] = stage.StartLine
	}
	return findings
}

// P015: relative WORKDIR
func checkRelativeWorkdir(instr dockerfile.Instruction) []analyzer.Finding {
	dir := strings.TrimSpace(instr.Args)
	if dir == "" || strings.HasPrefix(dir, "/") || strings.HasPrefix(dir, "$") {
		return nil
	}
	return []analyzer.Finding{{
		Line:     instr.Line,
		Severity: analyzer.Info,
		Category: analyzer.CategoryPerformance,
		RuleID:   "P015",
		Message:  fmt.Sprintf("WORKDIR %q is a relative path.", dir),
		Detail:   "A relative WORKDIR resolves against whatever the previous WORKDIR was, so its effective value depends on instruction order elsewhere in the file. Use an absolute path.",
	}}
}

// P016: hardcoded --platform on FROM
// pins the stage to one platform instead of using $BUILDPLATFORM/$TARGETPLATFORM, defeating multi-arch builds
func checkHardcodedPlatform(df *dockerfile.File) []analyzer.Finding {
	var findings []analyzer.Finding
	for _, instr := range df.Instructions {
		if instr.Cmd != "FROM" {
			continue
		}
		fields := strings.Fields(instr.Args)
		if len(fields) == 0 || !strings.HasPrefix(fields[0], "--platform=") {
			continue
		}
		value := strings.TrimPrefix(fields[0], "--platform=")
		if strings.Contains(value, "$") {
			continue // driven by a build arg which is the intended pattern
		}
		findings = append(findings, analyzer.Finding{
			Line:     instr.Line,
			Severity: analyzer.Info,
			Category: analyzer.CategoryPerformance,
			RuleID:   "P016",
			Message:  fmt.Sprintf("FROM --platform=%s is hardcoded.", value),
			Detail:   "Hardcoding --platform pins every build to one platform regardless of the host or --platform flag passed to `docker buildx build`. Use $BUILDPLATFORM (the build host's platform) or $TARGETPLATFORM (the platform being built for) instead.",
		})
	}
	return findings
}

// P014: RUN pipeline without pipefail. without it, a pipeline's exit code is only the last command's
// e.g., `curl bad-url | tar xz` "succeeds" despite curl failing
func checkMissingPipefail(a shellcmd.Analysis, instr dockerfile.Instruction, pipefailSet bool) []analyzer.Finding {
	if pipefailSet || len(a.PipePairs) == 0 {
		return nil
	}
	return []analyzer.Finding{{
		Line:     instr.Line,
		Severity: analyzer.Warning,
		Category: analyzer.CategoryPerformance,
		RuleID:   "P014",
		Message:  "Piped command without pipefail - a failure upstream of the last pipe stage won't fail the build.",
		Detail:   "Add `SHELL [\"/bin/bash\", \"-o\", \"pipefail\", \"-c\"]` before this RUN (requires bash - most `sh` implementations don't support -o pipefail) so the whole pipeline's exit code reflects any stage failing, not just the last one.",
	}}
}

// P007: heavy final base image
func checkFinalBaseImage(df *dockerfile.File) []analyzer.Finding {
	if len(df.Stages) == 0 {
		return nil
	}
	final := df.Stages[len(df.Stages)-1]
	if df.IsStageReference(final.BaseImage) {
		return nil
	}

	repo := imageref.RepoName(final.BaseImage)
	_, tag, _ := imageref.Parse(final.BaseImage)
	suggestion, heavy := imageref.HeavySuggestion(repo, tag)
	if !heavy {
		return nil
	}
	return []analyzer.Finding{{
		Line:     final.StartLine,
		Severity: analyzer.Info,
		Category: analyzer.CategoryPerformance,
		RuleID:   "P007",
		Message:  fmt.Sprintf("Final image is based on %q, a full-size base image.", final.BaseImage),
		Detail:   fmt.Sprintf("Consider %s to reduce final image size and memory footprint.", suggestion),
	}}
}

// P003: consecutive RUN instructions that could be chained
func checkConsecutiveRun(df *dockerfile.File) []analyzer.Finding {
	var findings []analyzer.Finding
	i := 0
	for i < len(df.Instructions) {
		if df.Instructions[i].Cmd != "RUN" {
			i++
			continue
		}
		j := i
		for j < len(df.Instructions) && df.Instructions[j].Cmd == "RUN" && df.Instructions[j].Stage == df.Instructions[i].Stage {
			j++
		}
		if count := j - i; count > 1 {
			findings = append(findings, analyzer.Finding{
				Line:     df.Instructions[i].Line,
				Severity: analyzer.Warning,
				Category: analyzer.CategoryPerformance,
				RuleID:   "P003",
				Message:  fmt.Sprintf("%d consecutive RUN instructions could be chained.", count),
				Detail:   "Combine with `&&` into a single RUN to avoid an extra image layer per command.",
			})
		}
		i = j
	}
	return findings
}
