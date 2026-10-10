package secrets

import "testing"

func TestScanValueKnownFormats(t *testing.T) {
	tests := []struct {
		name  string
		value string
		kind  string
	}{
		{"aws access key", "AKIAIOSFODNN7EXAMPLE", "AWS Access Key ID"},
		{"github token", "ghp_" + repeat("a1B2c3D4", 5), "GitHub Token"},
		{"gitlab pat", "glpat-XXXXXXXXXXXXXXXXXXXX", "GitLab Personal Access Token"},
		{"slack token", "xoxb-1234567890-abcdefghij", "Slack Token"},
		{"stripe live key", "sk_live_" + repeat("abcd1234", 4), "Stripe Live Key"},
		{"google api key", "AIza" + repeat("A", 35), "Google API Key"},
		{"npm token", "npm_" + repeat("a1B2c3D4", 5)[:36], "npm Access Token"},
		{"pem header", "-----BEGIN RSA PRIVATE KEY-----\nMIIB...\n-----END RSA PRIVATE KEY-----", "PEM Private Key"},
		{"jwt", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.dQw4w9WgXcQ_dQw4w9WgXcQ", "JSON Web Token"},
		{"basic auth url", "https://user:hunter2@example.com/path", "Basic Auth Credentials in URL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			matches := ScanValue(tt.value)
			if len(matches) == 0 {
				t.Fatalf("expected a match for %q, got none", tt.value)
			}
			found := false
			for _, m := range matches {
				if m.Kind == tt.kind {
					found = true
					if m.Confidence != High {
						t.Errorf("expected High confidence for a known format, got %v", m.Confidence)
					}
				}
			}
			if !found {
				t.Errorf("expected a %q match, got %+v", tt.kind, matches)
			}
		})
	}
}

func repeat(s string, n int) string {
	out := ""
	for i := 0; i < n; i++ {
		out += s
	}
	return out
}

func TestScanValueEntropyFallback(t *testing.T) {
	// No known format, but a long, high-randomness token - should still be
	// caught via entropy scoring.
	matches := ScanValue("aZ9kQ7mX2vB8nC4wE6rT1yU3iO5pL0sD")
	if len(matches) == 0 {
		t.Fatal("expected an entropy-based match for a high-randomness token")
	}
	if matches[0].Confidence != Medium {
		t.Errorf("expected Medium confidence for an entropy match, got %v", matches[0].Confidence)
	}
}

func TestScanValueNoFalsePositivesOnOrdinaryText(t *testing.T) {
	tests := []string{
		"production",
		"/usr/local/bin/node",
		"3000",
		"2024-01-15T10:30:00Z",
		"a short string",
		"18.20.4-alpine3.19",
		"550e8400-e29b-41d4-a716-446655440000", // UUID: mostly hex but has dashes breaking the token
		// Found via real-world validation against docker/awesome-compose's
		// spring-postgres example: a Docker-secrets-file pointer
		// (POSTGRES_PASSWORD_FILE's actual value, not a secret itself) and a
		// build ARG default that's a plain directory path. Both are long
		// enough, and varied enough in character mix once concatenated with
		// "/", to have previously fooled whole-string Shannon entropy scoring.
		"/run/secrets/db-password",
		"/workdir/server/target/dependency",
	}
	for _, v := range tests {
		t.Run(v, func(t *testing.T) {
			if matches := ScanValue(v); len(matches) != 0 {
				t.Errorf("did not expect a match for %q, got %+v", v, matches)
			}
		})
	}
}

func TestScanValueEntropyFallbackStillCatchesSecretAsPathSegment(t *testing.T) {
	// A real, common leak shape: a high-entropy secret stuffed into the last
	// segment of an otherwise ordinary-looking path (e.g. a mistakenly
	// hardcoded value where a *_FILE env var should have pointed at a
	// mounted secret instead). Splitting on "/" for entropy scoring must not
	// cost detection of this - each segment is still scored independently.
	matches := ScanValue("/run/secrets/aZ9kQ7mX2vB8nC4wE6rT1yU3iO5pL0sD")
	if len(matches) == 0 {
		t.Fatal("expected an entropy-based match for a high-entropy final path segment")
	}
	if matches[0].Value != "aZ9kQ7mX2vB8nC4wE6rT1yU3iO5pL0sD" {
		t.Errorf("matched value = %q, want just the high-entropy segment", matches[0].Value)
	}
}

func TestLooksLikeSecretName(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		{"API_SECRET", true},
		{"DB_PASSWORD", true},
		{"GITHUB_TOKEN", true},
		{"STRIPE_KEY", true},
		{"PRIVATE_KEY", true},
		{"BUILD_VERSION", false},
		{"NODE_ENV", false},
		{"PORT", false},
	}
	for _, tt := range tests {
		if got := LooksLikeSecretName(tt.name); got != tt.want {
			t.Errorf("LooksLikeSecretName(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}
