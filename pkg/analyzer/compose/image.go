package compose

import (
	"fmt"

	"github.com/onatribar/dockscribe/pkg/analyzer"
	"github.com/onatribar/dockscribe/pkg/imageref"
	"github.com/onatribar/dockscribe/pkg/parser/compose"
)

func checkImageReference(svc compose.Service) []analyzer.Finding {
	if svc.Build != nil || svc.Image == "" {
		return nil
	}

	var findings []analyzer.Finding
	findings = append(findings, checkMutableImageTag(svc)...)
	findings = append(findings, checkEOLImage(svc)...)
	return findings
}

// C016: mutable image tag
func checkMutableImageTag(svc compose.Service) []analyzer.Finding {
	_, tag, digest := imageref.Parse(svc.Image)
	if digest != "" {
		return nil
	}
	if tag != "" && !imageref.IsMutableTag(tag) {
		return nil
	}
	shown := tag
	if shown == "" {
		shown = "latest, implied"
	}
	return []analyzer.Finding{{
		Line:     svc.Line,
		Severity: analyzer.Info,
		Category: analyzer.CategorySecurity,
		RuleID:   "C016",
		Message:  fmt.Sprintf("Service %q's image %q uses a mutable tag (%s).", svc.Name, svc.Image, shown),
		Detail:   "Pin to a specific version or digest (e.g. `image@sha256:...`) so `docker compose pull` can't silently pick up a different image later.",
	}}
}

// C017: end-of-life image
func checkEOLImage(svc compose.Service) []analyzer.Finding {
	repo := imageref.RepoName(svc.Image)
	_, tag, _ := imageref.Parse(svc.Image)
	reason, isEOL := imageref.EOLReason(repo, tag)
	if !isEOL {
		return nil
	}
	return []analyzer.Finding{{
		Line:     svc.Line,
		Severity: analyzer.Warning,
		Category: analyzer.CategorySecurity,
		RuleID:   "C017",
		Message:  fmt.Sprintf("Service %q's image %q appears to be end-of-life.", svc.Name, svc.Image),
		Detail:   reason + " (This is a static, best-effort list and may be out of date - verify against the vendor's own support page.)",
	}}
}
