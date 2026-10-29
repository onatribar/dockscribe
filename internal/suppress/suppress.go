package suppress

import (
	"fmt"
	"regexp"
	"sort"
	"strings"

	"github.com/onatribar/dockscribe/pkg/analyzer"
)

const UnusedRuleID = "U001"
const wildcard = "*"

var ignoreRe = regexp.MustCompile(`(?i)^\s*#\s*dockscribe-ignore\b(.*)$`)

type Suppressions map[int]map[string]bool


func Parse(lines []string) Suppressions {
	out := Suppressions{}
	for i, line := range lines {
		m := ignoreRe.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		rest := strings.TrimSpace(m[1])
		rest = strings.TrimPrefix(rest, "=")
		rest = strings.TrimPrefix(rest, ":")
		rules := map[string]bool{}
		for _, r := range strings.Split(rest, ",") {
			if r = strings.ToUpper(strings.TrimSpace(r)); r != "" {
				rules[r] = true
			}
		}
		if len(rules) == 0 {
			continue
		}
		targetLine := i + 2
		out[targetLine] = rules
	}
	return out
}

func (s Suppressions) Matches(line int, ruleID string) bool {
	rules, ok := s[line]
	if !ok {
		return false
	}
	return rules[wildcard] || rules[strings.ToUpper(ruleID)]
}

func (s Suppressions) UnusedFindings(findings []analyzer.Finding) []analyzer.Finding {
	matched := map[int]map[string]bool{}
	for _, f := range findings {
		if matched[f.Line] == nil {
			matched[f.Line] = map[string]bool{}
		}
		matched[f.Line][strings.ToUpper(f.RuleID)] = true
	}

	type unused struct {
		line   int
		ruleID string
	}
	var list []unused
	for line, rules := range s {
		for rule := range rules {
			if rule != wildcard && !matched[line][rule] {
				list = append(list, unused{line, rule})
			}
		}
	}
	sort.Slice(list, func(i, j int) bool {
		if list[i].line != list[j].line {
			return list[i].line < list[j].line
		}
		return list[i].ruleID < list[j].ruleID
	})

	out := make([]analyzer.Finding, 0, len(list))
	for _, u := range list {
		out = append(out, analyzer.Finding{
			Line:     u.line,
			Severity: analyzer.Warning,
			Category: analyzer.CategorySuppression,
			RuleID:   UnusedRuleID,
			Message:  fmt.Sprintf("Suppression comment for %q on this line never matched a finding.", u.ruleID),
			Detail:   "Either the issue it silenced has since been fixed, the rule ID doesn't exist, or it's targeting the wrong line - a dockscribe-ignore comment only applies to the line directly below it. Remove it, or double check it's still needed.",
		})
	}
	return out
}