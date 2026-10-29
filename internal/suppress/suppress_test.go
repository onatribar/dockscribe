package suppress

import (
	"strings"
	"testing"

	"github.com/onatribar/dockscribe/pkg/analyzer"
)

func TestParseAndMatches(t *testing.T) {
	lines := []string{
		"FROM alpine",                        // 1
		"# dockscribe-ignore=S011",           // 2 -> suppresses line 3
		"RUN apt-get install -y curl",        // 3
		"# dockscribe-ignore S011,P002",      // 4 -> suppresses line 5 (no '=', comma list)
		"RUN apt-get install -y wget",        // 5
		"# dockscribe-ignore *",              // 6 -> suppresses everything on line 7
		"RUN sudo whatever",                  // 7
		"RUN apt-get install -y unaffected1", // 8, no comment above it
	}
	s := Parse(lines)

	tests := []struct {
		line   int
		ruleID string
		want   bool
	}{
		{3, "S011", true},
		{3, "P002", false},
		{5, "S011", true},
		{5, "P002", true},
		{5, "S008", false},
		{7, "S008", true},
		{7, "ANYTHING", true},
		{8, "S011", false},
		{1, "S011", false},
	}
	for _, tt := range tests {
		if got := s.Matches(tt.line, tt.ruleID); got != tt.want {
			t.Errorf("Matches(%d, %q) = %v, want %v", tt.line, tt.ruleID, got, tt.want)
		}
	}
}

func TestParseIgnoresBlankLineGap(t *testing.T) {
	lines := []string{
		"FROM alpine",
		"# dockscribe-ignore=S011",
		"",
		"RUN apt-get install -y curl",
	}
	s := Parse(lines)
	if s.Matches(4, "S011") {
		t.Error("did not expect the suppression to reach across a blank line")
	}
}

func TestParseIgnoresOrdinaryComments(t *testing.T) {
	lines := []string{
		"FROM alpine",
		"# just a regular comment, not a suppression",
		"RUN echo hi",
	}
	s := Parse(lines)
	if len(s) != 0 {
		t.Errorf("expected no suppressions from an ordinary comment, got %v", s)
	}
}

func TestParseEmptyRuleListIsIgnored(t *testing.T) {
	lines := []string{
		"FROM alpine",
		"# dockscribe-ignore=",
		"RUN echo hi",
	}
	s := Parse(lines)
	if len(s) != 0 {
		t.Errorf("expected a suppression comment with no rules to be a no-op, got %v", s)
	}
}

func TestMatchesOnUnknownLine(t *testing.T) {
	s := Suppressions{}
	if s.Matches(1, "S001") {
		t.Error("expected no match against an empty Suppressions")
	}
}

func TestUnusedFindingsNamedRuleNeverMatched(t *testing.T) {
	lines := []string{
		"FROM alpine",
		"# dockscribe-ignore=S011",
		"RUN echo hi",
	}
	s := Parse(lines)
	unused := s.UnusedFindings(nil)
	if len(unused) != 1 {
		t.Fatalf("expected 1 unused suppression, got %d: %+v", len(unused), unused)
	}
	got := unused[0]
	if got.Line != 3 || got.RuleID != UnusedRuleID || got.Category != analyzer.CategorySuppression || got.Severity != analyzer.Warning {
		t.Errorf("unused finding = %+v, want Line=3 RuleID=%s Category=suppression Severity=Warning", got, UnusedRuleID)
	}
	if !strings.Contains(got.Message, "S011") {
		t.Errorf("message = %q, want it to name S011", got.Message)
	}
}

func TestUnusedFindingsRuleThatDidMatchIsNotUnused(t *testing.T) {
	lines := []string{
		"FROM alpine",
		"# dockscribe-ignore=S011",
		"RUN echo hi",
	}
	s := Parse(lines)
	findings := []analyzer.Finding{{Line: 3, RuleID: "S011"}}
	if unused := s.UnusedFindings(findings); len(unused) != 0 {
		t.Errorf("expected no unused suppressions when the named rule did fire, got %+v", unused)
	}
}

func TestUnusedFindingsWildcardIsExempt(t *testing.T) {
	lines := []string{
		"FROM alpine",
		"# dockscribe-ignore=*",
		"RUN echo hi",
	}
	s := Parse(lines)
	if unused := s.UnusedFindings(nil); len(unused) != 0 {
		t.Errorf("expected the wildcard to never be reported as unused, got %+v", unused)
	}
}

func TestUnusedFindingsPartialMatchInMultiRuleList(t *testing.T) {
	lines := []string{
		"FROM alpine",
		"# dockscribe-ignore=S011,P002",
		"RUN apt-get install -y curl",
	}
	s := Parse(lines)
	findings := []analyzer.Finding{{Line: 3, RuleID: "P002"}}
	unused := s.UnusedFindings(findings)
	if len(unused) != 1 || unused[0].RuleID != UnusedRuleID {
		t.Fatalf("expected exactly 1 unused finding, got %+v", unused)
	}
	if !strings.Contains(unused[0].Message, "S011") {
		t.Errorf("message = %q, want it to name S011 specifically, not P002", unused[0].Message)
	}
}

func TestUnusedFindingsAreSortedDeterministically(t *testing.T) {
	lines := []string{
		"FROM alpine",
		"# dockscribe-ignore=S011,P002,S008",
		"RUN echo hi",
	}
	s := Parse(lines)
	for i := 0; i < 20; i++ {
		unused := s.UnusedFindings(nil)
		if len(unused) != 3 {
			t.Fatalf("run %d: expected 3 unused findings, got %d", i, len(unused))
		}
		want := []string{"P002", "S008", "S011"}
		for j, rule := range want {
			if unused[j].RuleID != UnusedRuleID || !strings.Contains(unused[j].Message, rule) {
				t.Fatalf("run %d: unused[%d] = %+v, want it to name %s", i, j, unused[j], rule)
			}
		}
	}
}
