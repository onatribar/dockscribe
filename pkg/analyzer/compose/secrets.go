package compose

import (
	"fmt"

	"github.com/onatribar/dockscribe/pkg/analyzer"
	"github.com/onatribar/dockscribe/pkg/parser/compose"
	"github.com/onatribar/dockscribe/pkg/secrets"
)

// C005/C006/C007: secret-looking environment values
func checkEnvironmentSecrets(svc compose.Service) []analyzer.Finding {
	var findings []analyzer.Finding
	for _, name := range analyzer.SortedKeys(svc.Environment) {
		value := svc.Environment[name]
		if secrets.LooksLikeSecretName(name) {
			findings = append(findings, analyzer.Finding{
				Line:     svc.Line,
				Severity: analyzer.Warning,
				Category: analyzer.CategorySecurity,
				RuleID:   "C005",
				Message:  fmt.Sprintf("Service %q environment variable %q looks like it holds a secret.", svc.Name, name),
				Detail:   "A value hardcoded in environment: is committed to version control in plaintext. Use an env_file excluded via .gitignore, Compose `secrets:`, or a secret manager instead.",
			})
		}
		for _, m := range secrets.ScanValue(value) {
			if m.Confidence == secrets.High {
				findings = append(findings, analyzer.Finding{
					Line:     svc.Line,
					Severity: analyzer.Error,
					Category: analyzer.CategorySecurity,
					RuleID:   "C006",
					Message:  fmt.Sprintf("Service %q environment variable %q's value matches a known %s format.", svc.Name, name, m.Kind),
					Detail:   "This looks like a real credential, not a placeholder, committed in plaintext. Rotate it immediately and move it to a secret manager or an untracked env_file.",
				})
			} else {
				findings = append(findings, analyzer.Finding{
					Line:     svc.Line,
					Severity: analyzer.Warning,
					Category: analyzer.CategorySecurity,
					RuleID:   "C007",
					Message:  fmt.Sprintf("Service %q environment variable %q's value looks like a high-entropy secret.", svc.Name, name),
					Detail:   "This value doesn't match a known credential format, but its randomness is consistent with a real secret rather than ordinary text. Verify it isn't a leaked key.",
				})
			}
		}
	}
	return findings
}
