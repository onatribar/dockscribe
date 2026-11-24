package sarif

import (
	"bytes"
	"encoding/json"
	"testing"

	"github.com/onatribar/dockscribe/pkg/analyzer"
	"github.com/onatribar/dockscribe/pkg/report"
)

type decodedLog struct {
	Version string `json:"version"`
	Runs    []struct {
		Tool struct {
			Driver struct {
				Name    string `json:"name"`
				Version string `json:"version"`
				Rules   []struct {
					ID         string `json:"id"`
					Properties struct {
						Tags             []string `json:"tags"`
						SecuritySeverity string   `json:"security-severity"`
					} `json:"properties"`
				} `json:"rules"`
			} `json:"driver"`
		} `json:"tool"`
		Results []struct {
			RuleID    string `json:"ruleId"`
			RuleIndex int    `json:"ruleIndex"`
			Level     string `json:"level"`
			Message   struct {
				Text string `json:"text"`
			} `json:"message"`
			Locations []struct {
				PhysicalLocation struct {
					ArtifactLocation struct {
						URI string `json:"uri"`
					} `json:"artifactLocation"`
					Region struct {
						StartLine int `json:"startLine"`
					} `json:"region"`
				} `json:"physicalLocation"`
			} `json:"locations"`
		} `json:"results"`
	} `json:"runs"`
}

func render(t *testing.T, reports ...report.Report) (decodedLog, string) {
	t.Helper()
	var buf bytes.Buffer
	r := New(&buf, "0.2.0")
	for _, rep := range reports {
		if err := r.Render(rep); err != nil {
			t.Fatalf("Render: %v", err)
		}
	}
	if err := r.Finish(); err != nil {
		t.Fatalf("Finish: %v", err)
	}
	var log decodedLog
	if err := json.Unmarshal(buf.Bytes(), &log); err != nil {
		t.Fatalf("output is not valid JSON: %v\n%s", err, buf.String())
	}
	if log.Version != "2.1.0" || len(log.Runs) != 1 {
		t.Fatalf("expected a SARIF 2.1.0 log with exactly one run, got:\n%s", buf.String())
	}
	return log, buf.String()
}

func TestRenderAcrossFiles(t *testing.T) {
	log, raw := render(t,
		report.Report{File: "app/Dockerfile", Findings: []analyzer.Finding{
			{Line: 3, Severity: analyzer.Error, Category: analyzer.CategorySecurity, RuleID: "S001", Message: "runs as root", Detail: "add USER"},
			{Line: 1, Severity: analyzer.Info, Category: analyzer.CategoryExplanation, Message: "Base image: alpine"},
			{Line: 2, Severity: analyzer.Info, Category: analyzer.CategoryPerformance, RuleID: "P005", Message: "no multi-stage"},
		}},
		report.Report{File: "docker-compose.yml", Findings: []analyzer.Finding{
			{Line: 0, Severity: analyzer.Warning, Category: analyzer.CategorySecurity, RuleID: "S001", Message: "runs as root"},
		}},
	)
	run := log.Runs[0]

	if run.Tool.Driver.Name != "dockscribe" || run.Tool.Driver.Version != "0.2.0" {
		t.Errorf("driver = %q %q, want dockscribe 0.2.0", run.Tool.Driver.Name, run.Tool.Driver.Version)
	}

	rules := run.Tool.Driver.Rules
	if len(rules) != 2 || rules[0].ID != "P005" || rules[1].ID != "S001" {
		t.Fatalf("rules should be deduplicated across files and sorted by ID, got:\n%s", raw)
	}
	if rules[1].Properties.SecuritySeverity == "" {
		t.Error("expected a security-severity on a security rule")
	}
	if rules[0].Properties.SecuritySeverity != "" {
		t.Error("did not expect a security-severity on a performance rule")
	}

	if len(run.Results) != 3 {
		t.Fatalf("expected 3 results (explanation lines skipped), got %d:\n%s", len(run.Results), raw)
	}
	for _, res := range run.Results {
		if rules[res.RuleIndex].ID != res.RuleID {
			t.Errorf("result %s has ruleIndex %d, which points at %s", res.RuleID, res.RuleIndex, rules[res.RuleIndex].ID)
		}
	}

	byURI := map[string]int{}
	for _, res := range run.Results {
		loc := res.Locations[0].PhysicalLocation
		byURI[loc.ArtifactLocation.URI]++
		if loc.Region.StartLine < 1 {
			t.Errorf("%s: startLine %d, SARIF lines are 1-based", res.RuleID, loc.Region.StartLine)
		}
	}
	if byURI["app/Dockerfile"] != 2 || byURI["docker-compose.yml"] != 1 {
		t.Errorf("results per file = %v, want app/Dockerfile:2 docker-compose.yml:1", byURI)
	}

	levels := map[string]bool{}
	for _, res := range run.Results {
		levels[res.Level] = true
		if res.RuleID == "S001" && res.Level == "error" && res.Message.Text != "runs as root\nadd USER" {
			t.Errorf("message = %q, want message and detail joined", res.Message.Text)
		}
	}
	for _, want := range []string{"error", "warning", "note"} {
		if !levels[want] {
			t.Errorf("expected a result with level %q (severity mapping), got levels %v", want, levels)
		}
	}
}

func TestRenderNoFindingsIsStillAValidLog(t *testing.T) {
	_, raw := render(t, report.Report{File: "Dockerfile"})
	if !bytes.Contains([]byte(raw), []byte(`"results": []`)) {
		t.Errorf("expected an empty results array, got:\n%s", raw)
	}
}
