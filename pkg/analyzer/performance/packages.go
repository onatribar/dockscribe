package performance

import (
	"fmt"

	"github.com/onatribar/dockscribe/pkg/analyzer"
	"github.com/onatribar/dockscribe/pkg/parser/dockerfile"
	"github.com/onatribar/dockscribe/pkg/shellcmd"
)

// P001: full context copied before dependency install
var depInstallCommands = map[string][]string{
	"npm":      {"ci", "install"},
	"yarn":     {"install"},
	"pnpm":     {"install"},
	"pip":      {"install"},
	"pip3":     {"install"},
	"bundle":   {"install"},
	"composer": {"install"},
	"go":       {"get"}, // "go mod download" handled separately below (two-word subcommand)
	"mvn":      {"install"},
	"gradle":   {"build"},
}

func isDependencyInstall(c shellcmd.Command) bool {
	if len(c.Args) == 0 {
		return false
	}
	if c.Name == "go" && len(c.Args) >= 2 && c.Args[0] == "mod" && c.Args[1] == "download" {
		return true
	}
	for _, sub := range depInstallCommands[c.Name] {
		if c.Args[0] == sub {
			return true
		}
	}
	return false
}

func checkEarlyBroadCopy(df *dockerfile.File) []analyzer.Finding {
	var findings []analyzer.Finding
	numStages := len(df.Stages)
	if numStages == 0 {
		numStages = 1
	}
	for stageIdx := 0; stageIdx < numStages; stageIdx++ {
		var broadCopyLine int
		for _, instr := range df.Instructions {
			if instr.Stage != stageIdx {
				continue
			}
			switch instr.Cmd {
			case "COPY":
				_, positional := dockerfile.SplitFlags(instr.Args)
				if broadCopyLine == 0 && isBroadCopy(positional) {
					broadCopyLine = instr.Line
				}
			case "RUN":
				if broadCopyLine == 0 {
					continue
				}
				a, ok := shellcmd.Analyze(dockerfile.StripLeadingRunFlags(instr.Args))
				if !ok {
					continue
				}
				installs := false
				for _, c := range a.Commands {
					if isDependencyInstall(c) {
						installs = true
						break
					}
				}
				if installs {
					findings = append(findings, analyzer.Finding{
						Line:     broadCopyLine,
						Severity: analyzer.Warning,
						Category: analyzer.CategoryPerformance,
						RuleID:   "P001",
						Message:  "Full build context copied before dependency installation.",
						Detail:   "Copy only dependency manifests (package.json, go.mod, requirements.txt, ...) first, install, then COPY the rest - source edits won't bust the dependency-install cache layer.",
					})
					broadCopyLine = 0
				}
			}
		}
	}
	return findings
}

func isBroadCopy(positional []string) bool {
	if len(positional) < 2 {
		return false
	}
	for _, s := range positional[:len(positional)-1] {
		if dockerfile.IsBroadCopySource(s) {
			return true
		}
	}
	return false
}

// P002: package manager cache not cleaned in the same layer
type pkgManagerRule struct {
	name       string
	command    string
	installArg string // args[0] that means "install a package"
	cleanRe    func(shellcmd.Analysis) bool
	hint       string
}

var pkgManagerRules = []pkgManagerRule{
	{
		name: "apt", command: "apt-get", installArg: "install",
		cleanRe: func(a shellcmd.Analysis) bool {
			return a.RemovesPath("/var/lib/apt/lists") || a.HasCommand("apt-get") && hasSubcommand(a, "apt-get", "clean")
		},
		hint: "&& rm -rf /var/lib/apt/lists/*",
	},
	{
		name: "apt", command: "apt", installArg: "install",
		cleanRe: func(a shellcmd.Analysis) bool {
			return a.RemovesPath("/var/lib/apt/lists") || hasSubcommand(a, "apt", "clean")
		},
		hint: "&& rm -rf /var/lib/apt/lists/*",
	},
	{
		name: "apk", command: "apk", installArg: "add",
		cleanRe: func(a shellcmd.Analysis) bool {
			return hasFlag(a, "apk", "--no-cache") || a.RemovesPath("/var/cache/apk") || hasSubcommand(a, "apk", "cache")
		},
		hint: "the --no-cache flag on `apk add`, or `rm -rf /var/cache/apk/*`",
	},
	{
		name: "yum", command: "yum", installArg: "install",
		cleanRe: func(a shellcmd.Analysis) bool { return hasSubcommand(a, "yum", "clean") },
		hint:    "&& yum clean all",
	},
	{
		name: "dnf", command: "dnf", installArg: "install",
		cleanRe: func(a shellcmd.Analysis) bool { return hasSubcommand(a, "dnf", "clean") },
		hint:    "&& dnf clean all",
	},
	{
		name: "pip", command: "pip", installArg: "install",
		cleanRe: func(a shellcmd.Analysis) bool { return hasFlag(a, "pip", "--no-cache-dir") },
		hint:    "--no-cache-dir to `pip install`",
	},
	{
		name: "pip", command: "pip3", installArg: "install",
		cleanRe: func(a shellcmd.Analysis) bool { return hasFlag(a, "pip3", "--no-cache-dir") },
		hint:    "--no-cache-dir to `pip3 install`",
	},
}

func hasSubcommand(a shellcmd.Analysis, name, sub string) bool {
	for _, c := range a.Commands {
		if c.Name == name && len(c.Args) > 0 && c.Args[0] == sub {
			return true
		}
	}
	return false
}

func hasFlag(a shellcmd.Analysis, name, flag string) bool {
	for _, c := range a.Commands {
		if c.Name != name {
			continue
		}
		for _, arg := range c.Args {
			if arg == flag {
				return true
			}
		}
	}
	return false
}

func checkPackageCacheCleanup(a shellcmd.Analysis, instr dockerfile.Instruction) []analyzer.Finding {
	var findings []analyzer.Finding
	seen := map[string]bool{} // rule.name already reported - apt-get and apt are separate table rows but the same tool, so a RUN using both shouldn't get flagged twice
	for _, rule := range pkgManagerRules {
		if seen[rule.name] {
			continue
		}
		installed := false
		for _, c := range a.Commands {
			if c.Name == rule.command && len(c.Args) > 0 && c.Args[0] == rule.installArg {
				installed = true
				break
			}
		}
		if !installed || rule.cleanRe(a) {
			continue
		}
		seen[rule.name] = true
		findings = append(findings, analyzer.Finding{
			Line:     instr.Line,
			Severity: analyzer.Warning,
			Category: analyzer.CategoryPerformance,
			RuleID:   "P002",
			Message:  fmt.Sprintf("%s cache not cleaned in the same RUN layer.", rule.name),
			Detail:   fmt.Sprintf("Add %s so the package cache doesn't get baked into the layer.", rule.hint),
		})
	}
	return findings
}

// P008: apt install without --no-install-recommends
func checkNoInstallRecommends(a shellcmd.Analysis, instr dockerfile.Instruction) []analyzer.Finding {
	for _, c := range a.Commands {
		if (c.Name != "apt-get" && c.Name != "apt") || len(c.Args) == 0 || c.Args[0] != "install" {
			continue
		}
		for _, arg := range c.Args[1:] {
			if arg == "--no-install-recommends" {
				return nil
			}
		}
		return []analyzer.Finding{{
			Line:     instr.Line,
			Severity: analyzer.Warning,
			Category: analyzer.CategoryPerformance,
			RuleID:   "P008",
			Message:  "apt/apt-get install without --no-install-recommends.",
			Detail:   "Recommended (but not required) packages get pulled in too, inflating the image. Add --no-install-recommends.",
		}}
	}
	return nil
}

// P009: apt-get update isolated from install
func checkAptUpdateAlone(a shellcmd.Analysis, instr dockerfile.Instruction) []analyzer.Finding {
	updates, installs := false, false
	for _, c := range a.Commands {
		if c.Name != "apt-get" && c.Name != "apt" {
			continue
		}
		if len(c.Args) == 0 {
			continue
		}
		switch c.Args[0] {
		case "update":
			updates = true
		case "install":
			installs = true
		}
	}
	if !updates || installs {
		return nil
	}
	return []analyzer.Finding{{
		Line:     instr.Line,
		Severity: analyzer.Warning,
		Category: analyzer.CategoryPerformance,
		RuleID:   "P009",
		Message:  "apt-get update runs in its own layer, separate from install.",
		Detail:   "Docker can cache this layer independently, so a later apt-get install may silently use a stale package index. Combine into one RUN: `apt-get update && apt-get install -y ...`.",
	}}
}
