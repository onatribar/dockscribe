package imageref

import "testing"

func TestParse(t *testing.T) {
	tests := []struct {
		ref        string
		wantRepo   string
		wantTag    string
		wantDigest string
	}{
		{"node:18-alpine", "node", "18-alpine", ""},
		{"node", "node", "", ""},
		{"node@sha256:abcdef0123", "node", "", "sha256:abcdef0123"},
		{"node:18@sha256:abcdef0123", "node", "18", "sha256:abcdef0123"},
		{"gcr.io/distroless/static-debian12", "gcr.io/distroless/static-debian12", "", ""},
		{"gcr.io/distroless/static-debian12:latest", "gcr.io/distroless/static-debian12", "latest", ""},
		{"myregistry:5000/app", "myregistry:5000/app", "", ""},
		{"myregistry:5000/app:1.0", "myregistry:5000/app", "1.0", ""},
	}

	for _, tt := range tests {
		t.Run(tt.ref, func(t *testing.T) {
			repo, tag, digest := Parse(tt.ref)
			if repo != tt.wantRepo || tag != tt.wantTag || digest != tt.wantDigest {
				t.Errorf("Parse(%q) = (%q, %q, %q), want (%q, %q, %q)",
					tt.ref, repo, tag, digest, tt.wantRepo, tt.wantTag, tt.wantDigest)
			}
		})
	}
}

func TestRepoName(t *testing.T) {
	tests := []struct {
		ref  string
		want string
	}{
		{"node:18-alpine", "node"},
		{"gcr.io/distroless/static-debian12:latest", "static-debian12"},
		{"golang", "golang"},
	}
	for _, tt := range tests {
		if got := RepoName(tt.ref); got != tt.want {
			t.Errorf("RepoName(%q) = %q, want %q", tt.ref, got, tt.want)
		}
	}
}

func TestIsMutableTag(t *testing.T) {
	tests := []struct {
		tag  string
		want bool
	}{
		{"latest", true},
		{"main", true},
		{"LATEST", true},
		{"18.20.4-alpine3.19", false},
		{"1.22", false},
		{"", false}, // empty tag ("defaults to latest") is a separate concern for callers
	}
	for _, tt := range tests {
		if got := IsMutableTag(tt.tag); got != tt.want {
			t.Errorf("IsMutableTag(%q) = %v, want %v", tt.tag, got, tt.want)
		}
	}
}

func TestEOLReason(t *testing.T) {
	tests := []struct {
		name    string
		repo    string
		tag     string
		wantEOL bool
	}{
		{"python 2", "python", "2.7", true},
		{"python current", "python", "3.12", false},
		{"python boundary: 3.1 must not match 3.10+", "python", "3.10", false},
		{"node 14", "node", "14", true},
		{"node current", "node", "22", false},
		{"ubuntu 18.04", "ubuntu", "18.04", true},
		{"ubuntu current", "ubuntu", "22.04", false},
		{"debian bullseye", "debian", "bullseye", true},
		{"centos any tag", "centos", "7", true},
		{"alpine boundary: 3.2 must not match 3.20+", "alpine", "3.22", false},
		{"unrelated repo", "distroless", "latest", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reason, isEOL := EOLReason(tt.repo, tt.tag)
			if isEOL != tt.wantEOL {
				t.Errorf("EOLReason(%q, %q) isEOL = %v, want %v", tt.repo, tt.tag, isEOL, tt.wantEOL)
			}
			if isEOL && reason == "" {
				t.Error("expected a non-empty reason when isEOL is true")
			}
		})
	}
}

func TestHeavySuggestion(t *testing.T) {
	tests := []struct {
		name      string
		repo      string
		tag       string
		wantHeavy bool
	}{
		{"heavy ubuntu", "ubuntu", "22.04", true},
		{"heavy node", "node", "18", true},
		{"node alpine variant", "node", "18-alpine", false},
		{"node slim variant", "node", "18-slim", false},
		{"unrelated repo", "distroless", "latest", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			suggestion, heavy := HeavySuggestion(tt.repo, tt.tag)
			if heavy != tt.wantHeavy {
				t.Errorf("HeavySuggestion(%q, %q) heavy = %v, want %v", tt.repo, tt.tag, heavy, tt.wantHeavy)
			}
			if heavy && suggestion == "" {
				t.Error("expected a non-empty suggestion when heavy is true")
			}
		})
	}
}
