package security

import (
	"fmt"

	"github.com/onatribar/dockscribe/pkg/analyzer"
	"github.com/onatribar/dockscribe/pkg/imageref"
	"github.com/onatribar/dockscribe/pkg/parser/dockerfile"
)

// S005: mutable base image tag

func checkMutableBaseImages(df *dockerfile.File) []analyzer.Finding {
	var findings []analyzer.Finding
	for _, stage := range df.Stages {
		if df.IsStageReference(stage.BaseImage) {
			continue
		}
		if f, flagged := mutableImageFinding(stage); flagged {
			findings = append(findings, f)
		}
	}
	return findings
}

func mutableImageFinding(stage dockerfile.Stage) (analyzer.Finding, bool) {
	_, tag, digest := imageref.Parse(stage.BaseImage)
	if digest != "" {
		return analyzer.Finding{}, false
	}
	if tag != "" && !imageref.IsMutableTag(tag) {
		return analyzer.Finding{}, false
	}
	shown := tag
	if shown == "" {
		shown = "latest, implied"
	}
	return analyzer.Finding{
		Line:     stage.StartLine,
		Severity: analyzer.Info,
		Category: analyzer.CategorySecurity,
		RuleID:   "S005",
		Message:  fmt.Sprintf("Base image %q uses a mutable tag (%s).", stage.BaseImage, shown),
		Detail:   "Pin to a specific version or digest (e.g. `image@sha256:...`) so builds are reproducible and can't be silently changed upstream.",
	}, true
}

// S018: end-of-life base image

func checkEOLBaseImages(df *dockerfile.File) []analyzer.Finding {
	var findings []analyzer.Finding
	for _, stage := range df.Stages {
		if df.IsStageReference(stage.BaseImage) {
			continue
		}
		repo := imageref.RepoName(stage.BaseImage)
		_, tag, _ := imageref.Parse(stage.BaseImage)
		reason, isEOL := imageref.EOLReason(repo, tag)
		if !isEOL {
			continue
		}
		findings = append(findings, analyzer.Finding{
			Line:     stage.StartLine,
			Severity: analyzer.Warning,
			Category: analyzer.CategorySecurity,
			RuleID:   "S018",
			Message:  fmt.Sprintf("Base image %q appears to be end-of-life.", stage.BaseImage),
			Detail:   reason + " (This is a static, best-effort list and may be out of date - verify against the vendor's own support page.)",
		})
	}
	return findings
}
