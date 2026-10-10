// Package secrets detects credential-shaped values in arbitrary text:
// known formats (AWS keys, GitHub tokens, PEM blocks, JWTs, ...) first,
// then Shannon-entropy scoring as a fallback for opaque random strings.
// Pure static analysis - nothing is sent anywhere or verified live.
package secrets

import (
	"math"
	"regexp"
	"strings"
)

// Confidence indicates how sure a Match is of being a real secret.
type Confidence string

const (
	High   Confidence = "high"   // matched a known, specific credential format
	Medium Confidence = "medium" // opaque high-entropy string; could be a secret, could be a hash/id
)

// Match is one detected secret-shaped value.
type Match struct {
	Kind       string // human-readable format name, e.g. "AWS Access Key ID", "high-entropy string"
	Value      string // the matched substring, as found (not redacted - callers decide how to present it)
	Confidence Confidence
}

type knownFormat struct {
	kind string
	re   *regexp.Regexp
}

// Specific, well-documented credential shapes used by major providers -
// precise enough that a match is a strong signal, not a guess.
var knownFormats = []knownFormat{
	{"AWS Access Key ID", regexp.MustCompile(`\b(AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[0-9A-Z]{16}\b`)},
	{"GitHub Token", regexp.MustCompile(`\bgh[pousr]_[A-Za-z0-9]{36,255}\b`)},
	{"GitLab Personal Access Token", regexp.MustCompile(`\bglpat-[A-Za-z0-9_-]{20}\b`)},
	{"Slack Token", regexp.MustCompile(`\bxox[baprs]-[A-Za-z0-9-]{10,72}\b`)},
	{"Slack Webhook URL", regexp.MustCompile(`https://hooks\.slack\.com/services/T[A-Za-z0-9_]+/B[A-Za-z0-9_]+/[A-Za-z0-9_]+`)},
	{"Stripe Live Key", regexp.MustCompile(`\bsk_live_[0-9a-zA-Z]{24,}\b`)},
	{"Google API Key", regexp.MustCompile(`\bAIza[0-9A-Za-z\-_]{35}\b`)},
	{"Google OAuth Client Secret", regexp.MustCompile(`\bGOCSPX-[A-Za-z0-9_-]{20,}\b`)},
	{"Twilio API Key", regexp.MustCompile(`\bSK[0-9a-fA-F]{32}\b`)},
	{"npm Access Token", regexp.MustCompile(`\bnpm_[A-Za-z0-9]{36}\b`)},
	{"PEM Private Key", regexp.MustCompile(`-----BEGIN (RSA |EC |OPENSSH |DSA |ENCRYPTED )?PRIVATE KEY-----`)},
	{"JSON Web Token", regexp.MustCompile(`\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b`)},
	{"Basic Auth Credentials in URL", regexp.MustCompile(`https?://[^\s/:@]+:[^\s/@]+@[^\s/]+`)},
}

// Falls back to entropy scoring on space-separated tokens only if no
// known format matched. Returns nil if nothing looks like a secret.
func ScanValue(value string) []Match {
	var matches []Match
	for _, kf := range knownFormats {
		for _, m := range kf.re.FindAllString(value, -1) {
			matches = append(matches, Match{Kind: kf.kind, Value: m, Confidence: High})
		}
	}
	if len(matches) > 0 {
		return matches
	}

	for _, tok := range tokenize(value) {
		if looksHighEntropy(tok) {
			matches = append(matches, Match{Kind: "high-entropy string", Value: tok, Confidence: Medium})
		}
	}
	return matches
}

// Splits on characters that wouldn't appear inside a single credential,
// including "/" - so a path like "/run/secrets/db-password" is scored per
// segment, not as one string whose concatenated words would otherwise
// fool whole-string entropy.
var tokenSplitRe = regexp.MustCompile(`[\s"'` + "`" + `,;/]+`)

func tokenize(value string) []string {
	return tokenSplitRe.Split(value, -1)
}

// Restricts entropy scoring to credential-shaped tokens (base64/hex/
// URL-safe), skipping sentences that would produce noisy false positives.
// No "/" needed - tokenize already split on it.
var entropyCandidateRe = regexp.MustCompile(`^[A-Za-z0-9+_.=-]+$`)

const (
	minEntropyTokenLen    = 20
	minEntropyBitsPerChar = 3.5
)

func looksHighEntropy(tok string) bool {
	if len(tok) < minEntropyTokenLen || len(tok) > 4096 {
		return false
	}
	if !entropyCandidateRe.MatchString(tok) {
		return false
	}
	// A token that's almost entirely digits (an id, a timestamp, a version
	// string) or almost entirely one repeated run isn't a credential.
	if isMostlyDigits(tok) {
		return false
	}
	return shannonEntropy(tok) >= minEntropyBitsPerChar
}

func isMostlyDigits(s string) bool {
	digits := 0
	for _, r := range s {
		if r >= '0' && r <= '9' {
			digits++
		}
	}
	return float64(digits)/float64(len(s)) > 0.85
}

// Bits of information per character: -sum(p*log2(p)) over each
// character's observed frequency p. Ordinary text sits well under 4
// bits/char; a random token sits near log2(alphabet size) (~6 for
// base64) - minEntropyBitsPerChar (3.5) sits between the two.
func shannonEntropy(s string) float64 {
	if s == "" {
		return 0
	}
	freq := make(map[rune]int, len(s))
	for _, r := range s {
		freq[r]++
	}
	n := float64(len(s))
	var entropy float64
	for _, count := range freq {
		p := float64(count) / n
		entropy -= p * math.Log2(p)
	}
	return entropy
}

// Case-insensitive substrings that make a variable/label name look like
// it's meant to hold a secret.
var nameSubstrings = []string{
	"SECRET", "TOKEN", "PASSWORD", "PASSWD", "CREDENTIAL", "_KEY", "APIKEY", "PRIVATE",
}

// A weak, high-recall signal (an ARG or ENV name, say) - pair with
// ScanValue on the actual value for a much stronger one.
func LooksLikeSecretName(name string) bool {
	upper := strings.ToUpper(name)
	for _, sub := range nameSubstrings {
		if strings.Contains(upper, sub) {
			return true
		}
	}
	return false
}
