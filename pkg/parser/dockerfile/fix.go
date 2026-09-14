package dockerfile

import (
	"regexp"
	"strings"

	"github.com/onatribar/dockscribe/pkg/shellcmd"
)

// fixer rewrites an instruction's Cmd/Args to resolve one rule
// ok is false if instruction doesn't match what the rule expects like if it's already fixed.
type fixer func(cmd, args string) (newCmd, newArgs string, ok bool)

// fixers holds every rule dockscribe knows how to safely auto-fix
// each is a pure text transformation with no guessed intent
// a rule like "missing HEALTHCHECK" shouldn't have a fixer since a wrong guess is worse than none
var fixers = map[string]fixer{
	"P002": func(cmd, args string) (string, string, bool) {
		newArgs, ok := fixPackageCache(args)
		return cmd, newArgs, ok
	},
	"P004": func(cmd, args string) (string, string, bool) {
		if cmd != "ADD" {
			return cmd, args, false
		}
		return "COPY", args, true
	},
	"P008": func(cmd, args string) (string, string, bool) {
		newArgs, ok := fixNoInstallRecommends(args)
		return cmd, newArgs, ok
	},
}

// FixInstruction proposes a rewritten Cmd/Args fixing one rule
// Cmd/Args may already reflect an earlier chained fix, so callers can apply several fixes by feeding each result into the next
// ok is false if dockscribe can't safely auto-fix that rule, or the instruction no longer matches what it expects.
// Only single-physical-line instructions (IsSingleLine) should be passed!!
func FixInstruction(cmd, args, ruleID string) (newCmd, newArgs string, ok bool) {
	fix, known := fixers[ruleID]
	if !known {
		return cmd, args, false
	}
	return fix(cmd, args)
}

// IsFixableRule reports whether FixInstruction knows how to fix ruleID at all.
// help decide which findings are even worth attempting before doing the per-instruction lookup.
func IsFixableRule(ruleID string) bool {
	_, known := fixers[ruleID]
	return known
}

// packageCacheFixes covers every package manager P002 detects (see
// pkg/analyzer/performance/packages.go's pkgManagerRules) - same install
// command/arg matched against, paired with how to fix that manager's cache.
var packageCacheFixes = []struct {
	command    string
	installArg string
	apply      func(args string) string
}{
	{"apt-get", "install", func(args string) string { return args + " && rm -rf /var/lib/apt/lists/*" }},
	{"apt", "install", func(args string) string { return args + " && rm -rf /var/lib/apt/lists/*" }},
	{"apk", "add", func(args string) string { return args + " && rm -rf /var/cache/apk/*" }},
	{"yum", "install", func(args string) string { return args + " && yum clean all" }},
	{"dnf", "install", func(args string) string { return args + " && dnf clean all" }},
	{"pip", "install", func(args string) string { return pipInstallForFix.ReplaceAllString(args, "$1$2 --no-cache-dir") }},
	{"pip3", "install", func(args string) string { return pipInstallForFix.ReplaceAllString(args, "$1$2 --no-cache-dir") }},
}

// fixPackageCache appends (or, for pip, inserts) a package-manager cache
// cleanup into a RUN command installing packages without one (P002).
func fixPackageCache(args string) (string, bool) {
	a, ok := shellcmd.Analyze(StripLeadingRunFlags(args))
	if !ok {
		return "", false
	}
	for _, fix := range packageCacheFixes {
		for _, c := range a.Commands {
			if c.Name == fix.command && len(c.Args) > 0 && c.Args[0] == fix.installArg {
				return fix.apply(args), true
			}
		}
	}
	return "", false
}

// aptInstallForFix matches "apt-get install" or "apt install" so the flag can be inserted immediately after "install"
var aptInstallForFix = regexp.MustCompile(`\b(apt-get|apt)(\s+install)\b`)

// pipInstallForFix matches "pip install" or "pip3 install" for the same reason.
var pipInstallForFix = regexp.MustCompile(`\b(pip3?)(\s+install)\b`)

// fixNoInstallRecommends inserts --no-install-recommends into an apt/apt-get install command that doesn't already have it
func fixNoInstallRecommends(args string) (string, bool) {
	if strings.Contains(args, "--no-install-recommends") {
		return "", false
	}
	if !aptInstallForFix.MatchString(args) {
		return "", false
	}
	return aptInstallForFix.ReplaceAllString(args, "$1$2 --no-install-recommends"), true
}
