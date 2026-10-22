package compose

import (
	"strings"
	"testing"
	"time"
)

func mustParse(t *testing.T, src string) *File {
	t.Helper()
	f, err := New().Parse([]byte(src))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	return f.(*File)
}

func TestCanParse(t *testing.T) {
	p := New()
	tests := []struct {
		name string
		want bool
	}{
		{"docker-compose.yml", true},
		{"docker-compose.yaml", true},
		{"compose.yml", true},
		{"compose.yaml", true},
		{"DOCKER-COMPOSE.YML", true},
		{"docker-compose.override.yml", true},
		{"docker-compose.prod.yaml", true},
		{"compose.dev.yaml", true},
		{"Dockerfile", false},
		{"stack.yml", false},
		{"docker-composeXyml", false},
	}
	for _, tt := range tests {
		if got := p.CanParse(tt.name); got != tt.want {
			t.Errorf("CanParse(%q) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

func TestParseEmptyFile(t *testing.T) {
	f := mustParse(t, "")
	if len(f.Services) != 0 {
		t.Errorf("expected 0 services for an empty file, got %d", len(f.Services))
	}
}

func TestParseNotYAML(t *testing.T) {
	src := "FROM alpine\nRUN echo hi : broken\n"
	if _, err := New().Parse([]byte(src)); err == nil {
		t.Error("expected an error for non-YAML content, got nil")
	}
}

func TestParseNotAMapping(t *testing.T) {
	src := "- eggs\n- milk\n- bread\n"
	_, err := New().Parse([]byte(src))
	if err == nil {
		t.Fatal("expected an error for a top-level YAML list, got nil")
	}
	if !strings.Contains(err.Error(), "not a mapping") {
		t.Errorf("error = %v, want it to mention the content isn't a mapping", err)
	}
}

func TestParseMissingServicesKey(t *testing.T) {
	src := "version: \"3\"\nnetworks:\n  default:\n"
	_, err := New().Parse([]byte(src))
	if err == nil {
		t.Fatal("expected an error when there's no top-level services: key, got nil")
	}
	if !strings.Contains(err.Error(), "services") {
		t.Errorf("error = %v, want it to mention the missing services key", err)
	}
}

func TestParseBasicService(t *testing.T) {
	src := "services:\n  web:\n    image: nginx:1.25\n    ports:\n      - \"80:80\"\n"
	f := mustParse(t, src)
	if f.ServiceCount() != 1 {
		t.Fatalf("expected 1 service, got %d", f.ServiceCount())
	}
	svc, ok := f.ServiceByName("web")
	if !ok {
		t.Fatal("expected to find service \"web\"")
	}
	if svc.Image != "nginx:1.25" {
		t.Errorf("Image = %q, want %q", svc.Image, "nginx:1.25")
	}
	if len(svc.Ports) != 1 || svc.Ports[0] != "80:80" {
		t.Errorf("Ports = %v, want [80:80]", svc.Ports)
	}
	if svc.Line != 2 {
		t.Errorf("Line = %d, want 2 (the \"web:\" key)", svc.Line)
	}
}

func TestParseBuildStringForm(t *testing.T) {
	f := mustParse(t, "services:\n  app:\n    build: ./app\n")
	svc, _ := f.ServiceByName("app")
	if svc.Build == nil {
		t.Fatal("expected a Build config")
	}
	if svc.Build.Context != "./app" || svc.Build.Dockerfile != "Dockerfile" {
		t.Errorf("Build = %+v, want Context=./app Dockerfile=Dockerfile", svc.Build)
	}
}

func TestParseBuildMappingForm(t *testing.T) {
	src := "services:\n  app:\n    build:\n      context: ./app\n      dockerfile: Dockerfile.prod\n      target: builder\n"
	f := mustParse(t, src)
	svc, _ := f.ServiceByName("app")
	want := BuildConfig{Context: "./app", Dockerfile: "Dockerfile.prod", Target: "builder"}
	if *svc.Build != want {
		t.Errorf("Build = %+v, want %+v", svc.Build, want)
	}
}

func TestParseEnvironmentMappingForm(t *testing.T) {
	f := mustParse(t, "services:\n  app:\n    environment:\n      DEBUG: \"true\"\n      API_KEY: secret123\n")
	svc, _ := f.ServiceByName("app")
	if svc.Environment["DEBUG"] != "true" || svc.Environment["API_KEY"] != "secret123" {
		t.Errorf("Environment = %v", svc.Environment)
	}
}

func TestParseEnvironmentListForm(t *testing.T) {
	f := mustParse(t, "services:\n  app:\n    environment:\n      - DEBUG=true\n      - INHERITED_FROM_HOST\n")
	svc, _ := f.ServiceByName("app")
	if svc.Environment["DEBUG"] != "true" {
		t.Errorf("Environment[DEBUG] = %q, want %q", svc.Environment["DEBUG"], "true")
	}
	if v, ok := svc.Environment["INHERITED_FROM_HOST"]; !ok || v != "" {
		t.Errorf("Environment[INHERITED_FROM_HOST] = %q, %v, want present with empty value", v, ok)
	}
}

func TestParseVolumesShortSyntax(t *testing.T) {
	src := "services:\n  app:\n    volumes:\n      - /home/user/.aws:/root/.aws:ro\n      - data:/var/lib/data\n      - /anon/target\n"
	f := mustParse(t, src)
	svc, _ := f.ServiceByName("app")
	if len(svc.Volumes) != 3 {
		t.Fatalf("expected 3 volumes, got %+v", svc.Volumes)
	}
	if svc.Volumes[0].Source != "/home/user/.aws" || svc.Volumes[0].Target != "/root/.aws" {
		t.Errorf("volume 0 = %+v", svc.Volumes[0])
	}
	if svc.Volumes[1].Source != "data" || svc.Volumes[1].Target != "/var/lib/data" {
		t.Errorf("volume 1 = %+v", svc.Volumes[1])
	}
	if svc.Volumes[2].Source != "" || svc.Volumes[2].Target != "/anon/target" {
		t.Errorf("volume 2 (anonymous) = %+v", svc.Volumes[2])
	}
}

func TestParseVolumesLongSyntax(t *testing.T) {
	src := "services:\n  app:\n    volumes:\n      - type: bind\n        source: /home/user/.ssh\n        target: /root/.ssh\n"
	f := mustParse(t, src)
	svc, _ := f.ServiceByName("app")
	if len(svc.Volumes) != 1 || svc.Volumes[0].Source != "/home/user/.ssh" || svc.Volumes[0].Target != "/root/.ssh" {
		t.Errorf("Volumes = %+v", svc.Volumes)
	}
}

func TestParseDependsOnListAndMapping(t *testing.T) {
	f := mustParse(t, "services:\n  web:\n    depends_on:\n      - db\n  db:\n    image: postgres\n")
	svc, _ := f.ServiceByName("web")
	if len(svc.DependsOn) != 1 || svc.DependsOn[0] != "db" {
		t.Errorf("DependsOn (list form) = %v", svc.DependsOn)
	}

	f2 := mustParse(t, "services:\n  web:\n    depends_on:\n      db:\n        condition: service_healthy\n  db:\n    image: postgres\n")
	svc2, _ := f2.ServiceByName("web")
	if len(svc2.DependsOn) != 1 || svc2.DependsOn[0] != "db" {
		t.Errorf("DependsOn (mapping form) = %v", svc2.DependsOn)
	}
}

func TestParsePrivilegedAndNetworkMode(t *testing.T) {
	f := mustParse(t, "services:\n  app:\n    privileged: true\n    network_mode: host\n    user: root\n")
	svc, _ := f.ServiceByName("app")
	if !svc.Privileged {
		t.Error("expected Privileged = true")
	}
	if svc.PrivilegedLine != 3 {
		t.Errorf("PrivilegedLine = %d, want 3", svc.PrivilegedLine)
	}
	if svc.NetworkMode != "host" {
		t.Errorf("NetworkMode = %q, want host", svc.NetworkMode)
	}
	if svc.User != "root" {
		t.Errorf("User = %q, want root", svc.User)
	}
}

func TestParseResourceLimitsModernAndLegacy(t *testing.T) {
	f := mustParse(t, "services:\n  a:\n    image: x\n    deploy:\n      resources:\n        limits:\n          cpus: \"0.5\"\n          memory: 256M\n  b:\n    image: x\n    mem_limit: 256m\n  c:\n    image: x\n")
	a, _ := f.ServiceByName("a")
	b, _ := f.ServiceByName("b")
	c, _ := f.ServiceByName("c")
	if !a.HasResourceLimits {
		t.Error("service a: expected HasResourceLimits = true (deploy.resources.limits)")
	}
	if !b.HasResourceLimits {
		t.Error("service b: expected HasResourceLimits = true (legacy mem_limit)")
	}
	if c.HasResourceLimits {
		t.Error("service c: expected HasResourceLimits = false (no limits set)")
	}
}

func TestParseResolvesAliasedEnvironment(t *testing.T) {
	src := "x-common: &common\n  DEBUG: \"true\"\n  LOG_LEVEL: info\nservices:\n  app:\n    image: x\n    environment: *common\n"
	f := mustParse(t, src)
	svc, _ := f.ServiceByName("app")
	if svc.Environment["DEBUG"] != "true" || svc.Environment["LOG_LEVEL"] != "info" {
		t.Errorf("Environment = %v, want the aliased block's values", svc.Environment)
	}
}

func TestParseResolvesAliasedSequenceItems(t *testing.T) {
	src := "x-cap: &cap SYS_PTRACE\nservices:\n  app:\n    image: x\n    cap_add:\n      - *cap\n"
	f := mustParse(t, src)
	svc, _ := f.ServiceByName("app")
	if len(svc.CapAdd) != 1 || svc.CapAdd[0] != "SYS_PTRACE" {
		t.Errorf("CapAdd = %v, want [SYS_PTRACE]", svc.CapAdd)
	}
}

func TestParseAliasChainDoesNotHang(t *testing.T) {
	src := "a: &a [\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\",\"x\"]\n" +
		"b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a]\n" +
		"c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b]\n" +
		"d: &d [*c,*c,*c,*c,*c,*c,*c,*c,*c]\n" +
		"e: &e [*d,*d,*d,*d,*d,*d,*d,*d,*d]\n" +
		"services:\n  app:\n    image: x\n    cap_add: *e\n"
	done := make(chan error, 1)
	go func() {
		_, err := New().Parse([]byte(src))
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("Parse: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Parse did not return within 2s on an aliased fan-out input")
	}
}

func TestFileType(t *testing.T) {
	f := mustParse(t, "services:\n  a:\n    image: x\n")
	if f.FileType() != "compose" {
		t.Errorf("FileType() = %q, want compose", f.FileType())
	}
}

func TestRawLinesPreservesSourceLineCount(t *testing.T) {
	f := mustParse(t, "services:\n  a:\n    image: x\n")
	if len(f.RawLines()) != 3 {
		t.Errorf("RawLines() len = %d, want 3", len(f.RawLines()))
	}
}
