package dockerignore

import (
	"reflect"
	"testing"
)

func TestParse(t *testing.T) {
	content := []byte("# comment\n\nnode_modules\n.git/\n!important.log\n  .env  \n")
	got := Parse(content)
	want := []string{"node_modules", ".git/", "!important.log", ".env"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("Parse() = %v, want %v", got, want)
	}
}

func TestExcludes(t *testing.T) {
	patterns := Parse([]byte("node_modules\n.git/\n*.pem\n"))

	tests := []struct {
		substr string
		want   bool
	}{
		{"node_modules", true},
		{".git", true},
		{"pem", true},
		{"id_rsa", false},
		{".env", false},
	}
	for _, tt := range tests {
		if got := Excludes(patterns, tt.substr); got != tt.want {
			t.Errorf("Excludes(patterns, %q) = %v, want %v", tt.substr, got, tt.want)
		}
	}
}

func TestExcludesIgnoresNegation(t *testing.T) {
	patterns := Parse([]byte("!.env\n"))
	if Excludes(patterns, ".env") {
		t.Error("a negated pattern should not count as excluding the path")
	}
}
