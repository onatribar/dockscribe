package compose

import (
	"fmt"
	"strings"

	"github.com/onatribar/dockscribe/pkg/analyzer"
	"github.com/onatribar/dockscribe/pkg/parser/compose"
)

type Analyzer struct{}

func New() *Analyzer { return &Analyzer{} }

func (a *Analyzer) Name() string { return "compose" }

func (a *Analyzer) Analyze(ctx analyzer.Context) ([]analyzer.Finding, error) {
	cf, ok := ctx.File.(*compose.File)
	if !ok || len(cf.Services) == 0 {
		return nil, nil
	}

	dfCache := map[string]*resolvedDockerfile{}
	var findings []analyzer.Finding
	for _, svc := range cf.Services {
		findings = append(findings, checkPrivileged(svc)...)
		findings = append(findings, checkHostNetwork(svc)...)
		findings = append(findings, checkUnconfinedSecurityOpt(svc)...)
		findings = append(findings, checkDangerousCapabilities(svc)...)
		findings = append(findings, checkSensitivePort(svc)...)
		findings = append(findings, checkNoResourceLimits(svc)...)
		findings = append(findings, checkNoRestartPolicy(svc)...)
		findings = append(findings, checkSensitiveMount(svc)...)
		findings = append(findings, checkDockerSocketMount(svc)...)
		findings = append(findings, checkEnvironmentSecrets(svc)...)
		findings = append(findings, checkImageReference(svc)...)
		findings = append(findings, checkBuildReference(svc, ctx, dfCache)...)
	}
	return findings, nil
}

// C001: privileged: true -> full device access
func checkPrivileged(svc compose.Service) []analyzer.Finding {
	if !svc.Privileged {
		return nil
	}
	return []analyzer.Finding{{
		Line:     svc.PrivilegedLine,
		Severity: analyzer.Error,
		Category: analyzer.CategorySecurity,
		RuleID:   "C001",
		Message:  fmt.Sprintf("Service %q runs privileged.", svc.Name),
		Detail:   "privileged: true grants the container nearly all capabilities of the host and disables its security confinement (seccomp, AppArmor, device restrictions). Use specific `cap_add:` entries for the one or two capabilities actually needed instead.",
	}}
}

// C003: network_mode: host
// Warning, not Error, since this may have legitimate uses
func checkHostNetwork(svc compose.Service) []analyzer.Finding {
	if svc.NetworkMode != "host" {
		return nil
	}
	return []analyzer.Finding{{
		Line:     svc.Line,
		Severity: analyzer.Warning,
		Category: analyzer.CategorySecurity,
		RuleID:   "C003",
		Message:  fmt.Sprintf("Service %q uses network_mode: host.", svc.Name),
		Detail:   "This removes network namespace isolation - the container shares the host's network stack directly. Use published `ports:` instead unless this service specifically needs host-level network access.",
	}}
}

// C013: unconfined seccomp/AppArmor profile
func checkUnconfinedSecurityOpt(svc compose.Service) []analyzer.Finding {
	for _, opt := range svc.SecurityOpt {
		lower := strings.ToLower(opt)
		if strings.Contains(lower, "unconfined") {
			return []analyzer.Finding{{
				Line:     svc.Line,
				Severity: analyzer.Warning,
				Category: analyzer.CategorySecurity,
				RuleID:   "C013",
				Message:  fmt.Sprintf("Service %q disables a security profile (%s).", svc.Name, opt),
				Detail:   "Docker's default seccomp/AppArmor profile blocks a large set of dangerous syscalls; \"unconfined\" turns that protection off entirely for this container (CIS Docker Benchmark 5.21).",
			}}
		}
	}
	return nil
}

// C014: dangerous added capabilities
var dangerousCapabilities = map[string]bool{
	"ALL": true, "SYS_ADMIN": true, "SYS_PTRACE": true, "SYS_MODULE": true, "SYS_RAWIO": true,
}

func checkDangerousCapabilities(svc compose.Service) []analyzer.Finding {
	for _, capability := range svc.CapAdd {
		if dangerousCapabilities[strings.ToUpper(capability)] {
			return []analyzer.Finding{{
				Line:     svc.Line,
				Severity: analyzer.Warning,
				Category: analyzer.CategorySecurity,
				RuleID:   "C014",
				Message:  fmt.Sprintf("Service %q adds capability %s.", svc.Name, capability),
				Detail:   "This capability grants broad, often ill-defined power close to full root. Add only the specific capability the process actually needs, if any of these was added out of habit rather than a verified requirement.",
			}}
		}
	}
	return nil
}

// C015: sensitive port published
var sensitivePorts = map[string]string{"22": "SSH", "23": "Telnet", "3389": "RDP"}

func checkSensitivePort(svc compose.Service) []analyzer.Finding {
	var findings []analyzer.Finding
	for _, mapping := range svc.Ports {
		field := mapping
		if i := strings.LastIndexByte(mapping, ':'); i >= 0 {
			field = mapping[i+1:]
		}
		if i := strings.IndexByte(field, '/'); i >= 0 {
			field = field[:i]
		}
		if proto, ok := sensitivePorts[field]; ok {
			findings = append(findings, analyzer.Finding{
				Line:     svc.Line,
				Severity: analyzer.Warning,
				Category: analyzer.CategorySecurity,
				RuleID:   "C015",
				Message:  fmt.Sprintf("Service %q publishes port %s, a %s port.", svc.Name, field, proto),
				Detail:   "Publishing a management/remote-access port from an application service is rarely intentional - double check this isn't a leftover from a debugging session or a copy-pasted base compose file.",
			})
		}
	}
	return findings
}

// C008: no resource limits
func checkNoResourceLimits(svc compose.Service) []analyzer.Finding {
	if svc.HasResourceLimits {
		return nil
	}
	return []analyzer.Finding{{
		Line:     svc.Line,
		Severity: analyzer.Info,
		Category: analyzer.CategoryPerformance,
		RuleID:   "C008",
		Message:  fmt.Sprintf("Service %q has no CPU/memory limits.", svc.Name),
		Detail:   "Without `deploy.resources.limits` (or the legacy `mem_limit`/`cpus`), a single misbehaving container can exhaust host resources and affect every other service on the same host.",
	}}
}

// C009: no restart policy
func checkNoRestartPolicy(svc compose.Service) []analyzer.Finding {
	restart := strings.ToLower(strings.TrimSpace(svc.Restart))
	if restart != "" && restart != "no" {
		return nil
	}
	return []analyzer.Finding{{
		Line:     svc.Line,
		Severity: analyzer.Info,
		Category: analyzer.CategoryPerformance,
		RuleID:   "C009",
		Message:  fmt.Sprintf("Service %q has no restart policy.", svc.Name),
		Detail:   "Without `restart:` (e.g. `unless-stopped` or `on-failure`), the service won't come back automatically after a crash or host reboot.",
	}}
}
