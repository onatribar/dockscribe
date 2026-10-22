package compose

import (
	"fmt"
	"strings"

	"github.com/onatribar/dockscribe/pkg/analyzer"
	"github.com/onatribar/dockscribe/pkg/parser/compose"
)

// C002: Docker socket bind-mounted
func checkDockerSocketMount(svc compose.Service) []analyzer.Finding {
	for _, v := range svc.Volumes {
		if strings.TrimSuffix(v.Source, "/") == "/var/run/docker.sock" {
			return []analyzer.Finding{{
				Line:     svc.Line,
				Severity: analyzer.Error,
				Category: analyzer.CategorySecurity,
				RuleID:   "C002",
				Message:  fmt.Sprintf("Service %q mounts the Docker socket into the container.", svc.Name),
				Detail:   "Access to /var/run/docker.sock is equivalent to root on the host - anyone able to reach this container can start a new privileged container and read/write the entire host filesystem through it. Use Docker's rootless mode, a socket proxy that filters the API, or avoid mounting the socket at all.",
			}}
		}
	}
	return nil
}

// C004: sensitive host path bind-mounted
var sensitiveMountPatterns = []string{
	".ssh", ".aws", ".gnupg", ".kube", ".docker/config.json",
	"id_rsa", "id_ed25519", ".netrc", ".pgpass", ".npmrc", "credentials",
}

func checkSensitiveMount(svc compose.Service) []analyzer.Finding {
	for _, v := range svc.Volumes {
		if v.Source == "" {
			continue // named/anonymous volume, not a host path
		}
		if isBroadHostRoot(v.Source) {
			return []analyzer.Finding{{
				Line:     svc.Line,
				Severity: analyzer.Warning,
				Category: analyzer.CategorySecurity,
				RuleID:   "C004",
				Message:  fmt.Sprintf("Service %q bind-mounts %q, the entire host root, into the container.", svc.Name, v.Source),
				Detail:   "Mounting \"/\" (or an equivalent broad path) gives the container read/write access to the whole host filesystem, including every credential and config file on it. Mount only the specific path this service actually needs.",
			}}
		}
		lower := strings.ToLower(v.Source)
		for _, pat := range sensitiveMountPatterns {
			if strings.Contains(lower, pat) {
				return []analyzer.Finding{{
					Line:     svc.Line,
					Severity: analyzer.Warning,
					Category: analyzer.CategorySecurity,
					RuleID:   "C004",
					Message:  fmt.Sprintf("Service %q bind-mounts a potentially sensitive host path (%s).", svc.Name, v.Source),
					Detail:   "Credentials and private keys mounted into a container are readable by anything running in it. If the service genuinely needs one of these (e.g. an SSH-based deploy step), mount only the single required file, read-only, rather than the whole containing directory.",
				}}
			}
		}
	}
	return nil
}

func isBroadHostRoot(source string) bool {
	trimmed := strings.TrimSuffix(source, "/")
	return trimmed == "" || trimmed == "/etc"
}
