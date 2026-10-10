package imageref

import "strings"

// splits an image reference into its repository, tag, and digest components.
//
// A colon after the last "/" is treated as a tag separator, so a "registry:port/name" host
// is not mistaken for a tag; anything after "@" is the digest.
func Parse(ref string) (repo, tag, digest string) {
	if i := strings.IndexByte(ref, '@'); i >= 0 {
		digest = ref[i+1:]
		ref = ref[:i]
	}
	lastSlash := strings.LastIndexByte(ref, '/')
	lastColon := strings.LastIndexByte(ref, ':')
	if lastColon > lastSlash {
		return ref[:lastColon], ref[lastColon+1:], digest
	}
	return ref, "", digest
}

// Strips any registry host/path prefix and tag/digest, e.g.
// "gcr.io/distroless/static-debian12:latest" -> "static-debian12".
func RepoName(ref string) string {
	repo, _, _ := Parse(ref)
	if i := strings.LastIndexByte(repo, '/'); i >= 0 {
		return repo[i+1:]
	}
	return repo
}

// Well-known floating/branch-like tags - not pinned to a specific,
// immutable release.
var mutableTagKeywords = map[string]bool{
	"latest": true, "edge": true, "nightly": true, "dev": true, "develop": true,
	"development": true, "master": true, "main": true, "stable": true,
	"rolling": true, "canary": true, "test": true, "testing": true,
}

// An empty tag (defaults to "latest") counts as mutable too - callers
// with tag "" should treat it as such.
func IsMutableTag(tag string) bool {
	return mutableTagKeywords[strings.ToLower(tag)]
}

type eolRule struct {
	repo     string
	prefixes []string // tag prefixes considered EOL; nil means the whole repo is deprecated
	reason   string
}

// Necessarily incomplete, checked against endoflife.date as of 2026-09.
// Will drift out of date; treat a miss as "not flagged," not "still
// supported."
var eolTable = []eolRule{
	{"python", []string{"2", "3.0", "3.1", "3.2", "3.3", "3.4", "3.5", "3.6", "3.7", "3.8", "3.9"},
		"This Python version is past its end-of-life date (python.org) and receives no security patches."},
	{"node", []string{"8", "10", "12", "14", "16", "17", "18", "19", "20", "21", "23", "25"},
		"This Node.js release line is past its end-of-life date (nodejs.org releases) and receives no security patches."},
	{"ubuntu", []string{"14.04", "16.04", "18.04", "20.04"},
		"This Ubuntu LTS release is past its standard 5-year support window (ubuntu.com/about/release-cycle)."},
	{"debian", []string{"8", "9", "10", "11", "jessie", "stretch", "buster", "bullseye"},
		"This Debian release is past its LTS support window (debian.org/releases)."},
	{"centos", nil,
		"CentOS Linux is fully end-of-life; the project moved to CentOS Stream (centos.org)."},
	{"alpine", []string{"3.9", "3.10", "3.11", "3.12", "3.13", "3.14", "3.15", "3.16", "3.17", "3.18", "3.19", "3.20"},
		"This Alpine version is past its support window (alpinelinux.org/releases)."},
}

func EOLReason(repo, tag string) (reason string, isEOL bool) {
	for _, rule := range eolTable {
		if !strings.EqualFold(repo, rule.repo) {
			continue
		}
		if eolTagMatches(tag, rule.prefixes) {
			return rule.reason, true
		}
	}
	return "", false
}

// A plain HasPrefix would wrongly match "3.10"-"3.19" against prefix
// "3.1"; guarded here against the next character being a digit.
func eolTagMatches(tag string, prefixes []string) bool {
	if len(prefixes) == 0 {
		return true
	}
	for _, p := range prefixes {
		if !strings.HasPrefix(tag, p) {
			continue
		}
		if len(tag) == len(p) {
			return true
		}
		if next := tag[len(p)]; next < '0' || next > '9' {
			return true
		}
	}
	return false
}

// Suggested slimmer alternative per repo, for repos with a well-known
// lightweight variant.
var heavyTable = map[string]string{
	"ubuntu":          "a slim/alpine base or a distroless equivalent",
	"debian":          "debian:*-slim or alpine",
	"centos":          "a minimal base such as alpine or UBI-minimal",
	"fedora":          "a minimal base such as alpine or UBI-minimal",
	"node":            "a node:*-alpine or node:*-slim tag",
	"python":          "a python:*-alpine or python:*-slim tag",
	"golang":          "a golang:*-alpine build stage, or distroless/scratch for the final stage",
	"openjdk":         "a *-jre or *-alpine tag",
	"eclipse-temurin": "a *-alpine tag",
}

// Not reported if tag already looks like a slimmer variant (contains
// "alpine", "slim", or "distroless").
func HeavySuggestion(repo, tag string) (suggestion string, isHeavy bool) {
	suggestion, heavy := heavyTable[strings.ToLower(repo)]
	if !heavy {
		return "", false
	}
	lowerTag := strings.ToLower(tag)
	if strings.Contains(lowerTag, "alpine") || strings.Contains(lowerTag, "slim") || strings.Contains(lowerTag, "distroless") {
		return "", false
	}
	return suggestion, true
}
