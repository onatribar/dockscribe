package compose

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/onatribar/dockscribe/pkg/parser"
	"gopkg.in/yaml.v3"
)

type BuildConfig struct {
	Context    string
	Dockerfile string // relative to Context; defaults to "Dockerfile"
	Target     string // build-stage name, if any
}

type VolumeMount struct {
	Source string
	Target string
}

type Service struct {
	Name              string
	Line              int
	Image             string
	Build             *BuildConfig
	Privileged        bool
	PrivilegedLine    int
	NetworkMode       string
	User              string
	Restart           string
	Ports             []string
	Volumes           []VolumeMount
	Environment       map[string]string
	CapAdd            []string
	SecurityOpt       []string
	DependsOn         []string
	HasResourceLimits bool
}

type File struct {
	lines    []string
	Services []Service
}

func (f *File) FileType() string   { return "compose" }
func (f *File) RawLines() []string { return f.lines }
func (f *File) ServiceCount() int { return len(f.Services) }

func (f *File) ServiceByName(name string) (Service, bool) {
	for _, s := range f.Services {
		if s.Name == name {
			return s, true
		}
	}
	return Service{}, false
}

type Parser struct{}

func New() *Parser { return &Parser{} }

func (p *Parser) CanParse(filename string) bool {
	base := strings.ToLower(filepath.Base(filename))
	for _, ext := range []string{".yml", ".yaml"} {
		if base == "compose"+ext || base == "docker-compose"+ext {
			return true
		}
		for _, stem := range []string{"compose.", "docker-compose."} {
			if strings.HasPrefix(base, stem) && strings.HasSuffix(base, ext) {
				return true
			}
		}
	}
	return false
}

func (p *Parser) Parse(src []byte) (parser.ParsedFile, error) {
	f := &File{lines: splitLines(src)}

	var doc yaml.Node
	if err := yaml.Unmarshal(src, &doc); err != nil {
		return nil, fmt.Errorf("not valid YAML: %w", err)
	}
	if len(doc.Content) == 0 {
		return f, nil 
	}

	root := doc.Content[0]
	if root.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("not a compose file: top-level content is a %s, not a mapping of keys like `services:`", nodeKindName(root.Kind))
	}

	var services *yaml.Node
	for k, v := range pairs(root) {
		if k.Value == "services" {
			services = v
		}
	}
	if services == nil {
		return nil, fmt.Errorf("not a compose file: no top-level `services:` key found")
	}
	if services.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("not a compose file: `services:` is not a mapping of service names")
	}

	for nameNode, svcNode := range pairs(services) {
		f.Services = append(f.Services, parseService(nameNode, svcNode))
	}
	return f, nil
}

func parseService(nameNode, svcNode *yaml.Node) Service {
	s := Service{Name: nameNode.Value, Line: nameNode.Line}
	if svcNode.Kind != yaml.MappingNode {
		return s
	}
	for k, v := range pairs(svcNode) {
		switch k.Value {
		case "image":
			s.Image = scalarString(v)
		case "build":
			s.Build = build(v)
		case "privileged":
			s.Privileged = scalarBool(v)
			s.PrivilegedLine = k.Line
		case "network_mode":
			s.NetworkMode = scalarString(v)
		case "user":
			s.User = scalarString(v)
		case "restart":
			s.Restart = scalarString(v)
		case "ports":
			s.Ports = stringList(v)
		case "volumes":
			s.Volumes = volumes(v)
		case "environment":
			s.Environment = environment(v)
		case "cap_add":
			s.CapAdd = stringList(v)
		case "security_opt":
			s.SecurityOpt = stringList(v)
		case "depends_on":
			s.DependsOn = dependsOn(v)
		}
	}
	s.HasResourceLimits = hasResourceLimits(svcNode)
	return s
}

func dependsOn(n *yaml.Node) []string {
	switch n.Kind {
	case yaml.SequenceNode:
		return stringList(n)
	case yaml.MappingNode:
		var names []string
		for k, _ := range pairs(n) {
			names = append(names, k.Value)
		}
		return names
	default:
		return nil
	}
}

func nodeKindName(k yaml.Kind) string {
	switch k {
	case yaml.SequenceNode:
		return "list"
	case yaml.ScalarNode:
		return "scalar value"
	case yaml.AliasNode:
		return "alias"
	default:
		return "document"
	}
}

func splitLines(src []byte) []string {
	if len(src) == 0 {
		return nil
	}
	return strings.Split(strings.TrimRight(string(src), "\n"), "\n")
}
