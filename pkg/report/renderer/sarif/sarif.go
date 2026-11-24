package sarif

import (
	"encoding/json"
	"io"
	"path/filepath"
	"sort"

	"github.com/onatribar/dockscribe/pkg/analyzer"
	"github.com/onatribar/dockscribe/pkg/report"
)

const (
	schemaURI      = "https://json.schemastore.org/sarif-2.1.0.json"
	informationURI = "https://github.com/onatribar/dockscribe"
)

type Renderer struct {
	Out     io.Writer
	Version string

	results []result
	rules   map[string]rule
}

func New(out io.Writer, version string) *Renderer {
	return &Renderer{Out: out, Version: version, rules: map[string]rule{}}
}

func (r *Renderer) Render(rep report.Report) error {
	uri := filepath.ToSlash(rep.File)
	for _, f := range rep.Findings {
		if f.RuleID == "" || f.Category == analyzer.CategoryExplanation {
			continue
		}
		if _, seen := r.rules[f.RuleID]; !seen {
			r.rules[f.RuleID] = newRule(f)
		}
		text := f.Message
		if f.Detail != "" {
			text += "\n" + f.Detail
		}
		r.results = append(r.results, result{
			RuleID:  f.RuleID,
			Level:   level(f.Severity),
			Message: message{Text: text},
			Locations: []location{{PhysicalLocation: physicalLocation{
				ArtifactLocation: artifactLocation{URI: uri},
				Region: region{StartLine: max(f.Line, 1)},
			}}},
		})
	}
	return nil
}

func (r *Renderer) Finish() error {
	ids := analyzer.SortedKeys(r.rules)
	rules := make([]rule, 0, len(ids))
	index := make(map[string]int, len(ids))
	for i, id := range ids {
		rules = append(rules, r.rules[id])
		index[id] = i
	}
	results := make([]result, len(r.results))
	for i, res := range r.results {
		res.RuleIndex = index[res.RuleID]
		results[i] = res
	}
	sort.SliceStable(results, func(i, j int) bool {
		a, b := results[i].Locations[0].PhysicalLocation, results[j].Locations[0].PhysicalLocation
		if a.ArtifactLocation.URI != b.ArtifactLocation.URI {
			return a.ArtifactLocation.URI < b.ArtifactLocation.URI
		}
		return a.Region.StartLine < b.Region.StartLine
	})

	log := sarifLog{
		Schema:  schemaURI,
		Version: "2.1.0",
		Runs: []run{{
			Tool: tool{Driver: driver{
				Name:           "dockscribe",
				InformationURI: informationURI,
				Version:        r.Version,
				Rules:          rules,
			}},
			Results: results,
		}},
	}
	enc := json.NewEncoder(r.Out)
	enc.SetIndent("", "  ")
	return enc.Encode(log)
}

func level(s analyzer.Severity) string {
	switch s {
	case analyzer.Error:
		return "error"
	case analyzer.Warning:
		return "warning"
	default:
		return "note"
	}
}

func securitySeverity(s analyzer.Severity) string {
	switch s {
	case analyzer.Error:
		return "8.0"
	case analyzer.Warning:
		return "5.0"
	default:
		return "2.0"
	}
}

func newRule(f analyzer.Finding) rule {
	ru := rule{
		ID:               f.RuleID,
		ShortDescription: message{Text: f.RuleID},
		DefaultConfiguration: &configuration{
			Level: level(f.Severity),
		},
		Properties: properties{Tags: []string{string(f.Category)}},
	}
	if f.Category == analyzer.CategorySecurity {
		ru.Properties.SecuritySeverity = securitySeverity(f.Severity)
	}
	return ru
}

type sarifLog struct {
	Schema  string `json:"$schema"`
	Version string `json:"version"`
	Runs    []run  `json:"runs"`
}

type run struct {
	Tool    tool     `json:"tool"`
	Results []result `json:"results"`
}

type tool struct {
	Driver driver `json:"driver"`
}

type driver struct {
	Name           string `json:"name"`
	InformationURI string `json:"informationUri"`
	Version        string `json:"version,omitempty"`
	Rules          []rule `json:"rules"`
}

type rule struct {
	ID                   string         `json:"id"`
	ShortDescription     message        `json:"shortDescription"`
	DefaultConfiguration *configuration `json:"defaultConfiguration,omitempty"`
	Properties           properties     `json:"properties"`
}

type configuration struct {
	Level string `json:"level"`
}

type properties struct {
	Tags             []string `json:"tags,omitempty"`
	SecuritySeverity string   `json:"security-severity,omitempty"`
}

type result struct {
	RuleID    string     `json:"ruleId"`
	RuleIndex int        `json:"ruleIndex"`
	Level     string     `json:"level"`
	Message   message    `json:"message"`
	Locations []location `json:"locations"`
}

type message struct {
	Text string `json:"text"`
}

type location struct {
	PhysicalLocation physicalLocation `json:"physicalLocation"`
}

type physicalLocation struct {
	ArtifactLocation artifactLocation `json:"artifactLocation"`
	Region           region           `json:"region"`
}

type artifactLocation struct {
	URI string `json:"uri"`
}

type region struct {
	StartLine int `json:"startLine"`
}
