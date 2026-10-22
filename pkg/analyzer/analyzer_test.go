package analyzer

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestSeverityString(t *testing.T) {
	tests := []struct {
		s    Severity
		want string
	}{
		{Info, "INFO"},
		{Warning, "WARN"},
		{Error, "ERROR"},
		{Severity(99), "UNKNOWN"},
	}
	for _, tt := range tests {
		if got := tt.s.String(); got != tt.want {
			t.Errorf("Severity(%d).String() = %q, want %q", tt.s, got, tt.want)
		}
	}
}

func TestSeverityOrdering(t *testing.T) {
	if !(Info < Warning && Warning < Error) {
		t.Error("expected Info < Warning < Error so --severity/--fail-on threshold comparisons work")
	}
}

func TestSeverityMarshalJSON(t *testing.T) {
	b, err := json.Marshal(Warning)
	if err != nil {
		t.Fatal(err)
	}
	if string(b) != `"WARN"` {
		t.Errorf("MarshalJSON = %s, want %q", b, `"WARN"`)
	}
}

func TestFindingMarshalsSeverityAsString(t *testing.T) {
	f := Finding{Line: 1, Severity: Error, Category: CategorySecurity, Message: "x"}
	b, err := json.Marshal(f)
	if err != nil {
		t.Fatal(err)
	}
	var raw map[string]any
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	if raw["severity"] != "ERROR" {
		t.Errorf("severity = %v, want ERROR", raw["severity"])
	}
	if _, present := raw["rule_id"]; present {
		t.Error("expected rule_id to be omitted (omitempty) when RuleID is unset")
	}
}

func TestParseSeverity(t *testing.T) {
	tests := []struct {
		in     string
		want   Severity
		wantOK bool
	}{
		{"info", Info, true},
		{"INFO", Info, true},
		{"  warning  ", Warning, true},
		{"warn", Warning, true},
		{"error", Error, true},
		{"bogus", Info, false},
		{"", Info, false},
	}
	for _, tt := range tests {
		got, ok := ParseSeverity(tt.in)
		if got != tt.want || ok != tt.wantOK {
			t.Errorf("ParseSeverity(%q) = (%v, %v), want (%v, %v)", tt.in, got, ok, tt.want, tt.wantOK)
		}
	}
}

func TestSortedKeys(t *testing.T) {
	got := SortedKeys(map[string]string{"zebra": "1", "apple": "2", "mango": "3"})
	want := []string{"apple", "mango", "zebra"}
	if len(got) != len(want) {
		t.Fatalf("SortedKeys = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("SortedKeys = %v, want %v", got, want)
			break
		}
	}

	if got := SortedKeys(map[string]bool{}); len(got) != 0 {
		t.Errorf("SortedKeys(empty map) = %v, want empty", got)
	}
	if got := SortedKeys[bool](nil); len(got) != 0 {
		t.Errorf("SortedKeys(nil map) = %v, want empty", got)
	}
}

func TestContextReadSibling(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "sibling.txt"), []byte("hello"), 0o644); err != nil {
		t.Fatal(err)
	}

	ctx := Context{Dir: dir}
	content, ok := ctx.ReadSibling("sibling.txt")
	if !ok || string(content) != "hello" {
		t.Errorf("ReadSibling(sibling.txt) = %q, %v, want \"hello\", true", content, ok)
	}

	if _, ok := ctx.ReadSibling("does-not-exist.txt"); ok {
		t.Error("expected ok=false for a missing sibling file")
	}

	empty := Context{}
	if _, ok := empty.ReadSibling("sibling.txt"); ok {
		t.Error("expected ok=false when Dir is unset")
	}
}
