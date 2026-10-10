package security

import (
	"fmt"
	"strings"

	"github.com/onatribar/dockscribe/pkg/analyzer"
	"github.com/onatribar/dockscribe/pkg/parser/dockerfile"
	"github.com/onatribar/dockscribe/pkg/shellcmd"
)

var shellInterpreters = map[string]bool{"sh": true, "bash": true, "zsh": true, "ash": true, "dash": true}
var fetchCommands = map[string]bool{"curl": true, "wget": true}

// S006: curl/wget piped into a shell

// catch fetch commands that eventually end up in shell somewhere down the line
func checkCurlPipeShell(a shellcmd.Analysis, instr dockerfile.Instruction) []analyzer.Finding {
	// adjacency list of "pipes into" relationships so a relay chain can be identified
	adj := map[string][]string{}
	for _, pair := range a.PipePairs {
		to := pair.To.Name
		if to == "sudo" && len(pair.To.Args) > 0 {
			to = pair.To.Args[0]
		}
		adj[pair.From.Name] = append(adj[pair.From.Name], to)
	}

	for start := range adj {
		if fetchCommands[start] && reachesShell(adj, start, map[string]bool{}) {
			return []analyzer.Finding{{
				Line:     instr.Line,
				Severity: analyzer.Warning,
				Category: analyzer.CategorySecurity,
				RuleID:   "S006",
				Message:  "Pipes a remote script directly into a shell.",
				Detail:   "Download to a file, verify its checksum/signature, then execute - piping curl/wget straight into a shell runs unverified remote code.",
			}}
		}
	}
	return nil
}

func reachesShell(adj map[string][]string, node string, visited map[string]bool) bool {
	if visited[node] {
		return false
	}
	visited[node] = true
	for _, next := range adj[node] {
		if shellInterpreters[next] || reachesShell(adj, next, visited) {
			return true
		}
	}
	return false
}

// S008: sudo inside RUN

func checkSudo(a shellcmd.Analysis, instr dockerfile.Instruction) []analyzer.Finding {
	if !a.HasCommand("sudo") {
		return nil
	}
	return []analyzer.Finding{{
		Line:     instr.Line,
		Severity: analyzer.Warning,
		Category: analyzer.CategorySecurity,
		RuleID:   "S008",
		Message:  "RUN instruction uses sudo.",
		Detail:   "RUN already executes as the image's current user (root by default); sudo is unnecessary and often a leftover assumption from outside a container.",
	}}
}

// S011: unpinned package install (apt/apt-get/apk)

var unpinnedCheckCommands = map[string]string{
	"apt-get": "install",
	"apt":     "install",
	"apk":     "add",
}

func checkUnpinnedPackageInstall(a shellcmd.Analysis, instr dockerfile.Instruction) []analyzer.Finding {
	for _, c := range a.Commands {
		install, known := unpinnedCheckCommands[c.Name]
		if !known || len(c.Args) == 0 || c.Args[0] != install {
			continue
		}
		hasPackage, allPinned := false, true
		for _, arg := range c.Args[1:] {
			if strings.HasPrefix(arg, "-") {
				continue
			}
			hasPackage = true
			if !strings.Contains(arg, "=") {
				allPinned = false
			}
		}
		if hasPackage && !allPinned {
			return []analyzer.Finding{{
				Line:     instr.Line,
				Severity: analyzer.Info,
				Category: analyzer.CategorySecurity,
				RuleID:   "S011",
				Message:  fmt.Sprintf("%s install without version pins.", c.Name),
				Detail:   "Pin package versions (e.g. `package=1.2.3-1`) so a rebuild can't silently pull in a different, potentially vulnerable version.",
			}}
		}
	}
	return nil
}

// S012: TLS verification disabled

var insecureTLSFlags = map[string]bool{"-k": true, "--insecure": true, "--no-check-certificate": true}

func checkInsecureTLS(a shellcmd.Analysis, instr dockerfile.Instruction) []analyzer.Finding {
	for _, c := range a.Commands {
		if !fetchCommands[c.Name] {
			continue
		}
		for _, arg := range c.Args {
			if insecureTLSFlags[arg] {
				return []analyzer.Finding{{
					Line:     instr.Line,
					Severity: analyzer.Warning,
					Category: analyzer.CategorySecurity,
					RuleID:   "S012",
					Message:  "Disables TLS certificate verification.",
					Detail:   "Flags like -k/--insecure/--no-check-certificate leave the download open to man-in-the-middle tampering.",
				}}
			}
		}
	}
	return nil
}
