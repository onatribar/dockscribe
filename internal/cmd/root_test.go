package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/onatribar/dockscribe/internal/registry"
	"github.com/onatribar/dockscribe/pkg/analyzer"
)

func TestParseFailOn(t *testing.T) {
	tests := []struct {
		in        string
		wantNever bool
		wantOK    bool
	}{
		{"never", true, true},
		{"Never", true, true},
		{" never ", true, true},
		{"info", false, true},
		{"warning", false, true},
		{"error", false, true},
		{"bogus", false, false},
		{"", false, false},
	}
	for _, tt := range tests {
		t.Run(tt.in, func(t *testing.T) {
			never, _, ok := parseFailOn(tt.in)
			if never != tt.wantNever || ok != tt.wantOK {
				t.Errorf("parseFailOn(%q) = (never=%v, ok=%v), want (never=%v, ok=%v)", tt.in, never, ok, tt.wantNever, tt.wantOK)
			}
		})
	}
}

func TestParseFailOnThresholdMatchesSeverity(t *testing.T) {
	_, threshold, ok := parseFailOn("warning")
	if !ok || threshold != analyzer.Warning {
		t.Errorf("parseFailOn(\"warning\") threshold = %v, ok = %v, want analyzer.Warning, true", threshold, ok)
	}
}

// resetFlags restores every package-level flag var to its registered
// default. cobra/pflag only calls Set() for flags actually present in the
// next argv, so without this, a value from one Execute() call would leak
// into the next test that omits that flag.
func resetFlags(t *testing.T) {
	t.Helper()
	formatFlag = "text"
	severityFlag = "info"
	noExplainFlag = false
	onlyFlag = ""
	failOnFlag = "error"
	fixFlag = false
	typeFlag = ""
	baselineFlag = ""
	writeBaselineFlag = ""
}

func TestExpandPathsPassesThroughPlainFiles(t *testing.T) {
	reg := registry.New()
	got, err := expandPaths(reg, []string{"Dockerfile", "docker-compose.yml"})
	if err != nil {
		t.Fatalf("expandPaths: %v", err)
	}
	want := []string{"Dockerfile", "docker-compose.yml"}
	if len(got) != len(want) || got[0] != want[0] || got[1] != want[1] {
		t.Errorf("expandPaths(plain files) = %v, want %v (unchanged, no filesystem access needed)", got, want)
	}
}

func TestExpandPathsScansDirectoryRecursively(t *testing.T) {
	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(repoRoot, "testdata", "compose")

	reg := registry.New()
	got, err := expandPaths(reg, []string{dir})
	if err != nil {
		t.Fatalf("expandPaths: %v", err)
	}

	want := map[string]bool{
		filepath.Join(dir, "docker-compose.clean.yml"):              true,
		filepath.Join(dir, "docker-compose.insecure.yml"):           true,
		filepath.Join(dir, "build-reference", "Dockerfile"):         true,
		filepath.Join(dir, "build-reference", "docker-compose.yml"): true,
	}
	if len(got) != len(want) {
		t.Fatalf("expandPaths(%s) = %v, want %d files matching %v", dir, got, len(want), want)
	}
	for _, path := range got {
		if !want[path] {
			t.Errorf("unexpected file discovered: %s", path)
		}
	}
}

func TestExpandPathsSkipsHeavyDirs(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "node_modules"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "node_modules", "Dockerfile"), []byte("FROM alpine\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte("FROM alpine\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	reg := registry.New()
	got, err := expandPaths(reg, []string{dir})
	if err != nil {
		t.Fatalf("expandPaths: %v", err)
	}
	if len(got) != 1 || got[0] != filepath.Join(dir, "Dockerfile") {
		t.Errorf("expandPaths = %v, want only the top-level Dockerfile (node_modules skipped)", got)
	}
}

func TestExecuteDirectoryArgumentScansAllFixtures(t *testing.T) {
	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	resetFlags(t)
	rootCmd.SetArgs([]string{"--no-explain", "--fail-on", "never", filepath.Join(repoRoot, "testdata", "compose")})
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&bytes.Buffer{})

	if got := Execute(); got != 0 {
		t.Fatalf("Execute() = %d, want 0 (--fail-on never); output:\n%s", got, out.String())
	}
	for _, want := range []string{"docker-compose.clean.yml", "docker-compose.insecure.yml", "build-reference/Dockerfile", "build-reference/docker-compose.yml"} {
		if !bytes.Contains(out.Bytes(), []byte(want)) {
			t.Errorf("output missing report for %s; got:\n%s", want, out.String())
		}
	}
}

func TestExecuteSuppressesIgnoredFindings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Dockerfile")
	src := "FROM ubuntu:22.04\n" +
		"# dockscribe-ignore=S001\n" +
		"CMD [\"/app\"]\n"
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	resetFlags(t)
	rootCmd.SetArgs([]string{"--no-explain", "--fail-on", "never", path})
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&bytes.Buffer{})

	if got := Execute(); got != 0 {
		t.Fatalf("Execute() = %d, want 0; output:\n%s", got, out.String())
	}
	if bytes.Contains(out.Bytes(), []byte("S001")) {
		t.Errorf("expected S001 to be suppressed, got:\n%s", out.String())
	}
}

func TestExecuteSuppressionAppliesToComposeFindingsToo(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "docker-compose.yml")
	// C008 (no resource limits) attributes to the service's own key line
	// ("app:"), so the suppression comment - which targets the line
	// directly below it - must sit one line above that, not above image:.
	src := "services:\n" +
		"  # dockscribe-ignore=C008\n" +
		"  app:\n" +
		"    image: nginx:1.25.3\n"
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	resetFlags(t)
	rootCmd.SetArgs([]string{"--no-explain", "--fail-on", "never", path})
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&bytes.Buffer{})

	if got := Execute(); got != 0 {
		t.Fatalf("Execute() = %d, want 0; output:\n%s", got, out.String())
	}
	if bytes.Contains(out.Bytes(), []byte("C008")) {
		t.Errorf("expected C008 to be suppressed on a compose file too, got:\n%s", out.String())
	}
}

func TestExecuteWarnsOnUnusedSuppression(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Dockerfile")
	// S011 is named but nothing on the RUN line below ever triggers it
	// (the package is version-pinned) - the suppression comment is stale.
	src := "FROM ubuntu:22.04\n" +
		"# dockscribe-ignore=S011\n" +
		"RUN apt-get install -y curl=7.81.0-1ubuntu1\n" +
		"USER app\n"
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	resetFlags(t)
	rootCmd.SetArgs([]string{"--no-explain", "--fail-on", "never", path})
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&bytes.Buffer{})

	if got := Execute(); got != 0 {
		t.Fatalf("Execute() = %d, want 0; output:\n%s", got, out.String())
	}
	if !bytes.Contains(out.Bytes(), []byte("U001")) || !bytes.Contains(out.Bytes(), []byte("S011")) {
		t.Errorf("expected a U001 finding naming the unused S011 suppression, got:\n%s", out.String())
	}
}

func TestExecuteNoWarningWhenSuppressionIsUsed(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Dockerfile")
	src := "FROM ubuntu:22.04\n" +
		"# dockscribe-ignore=S011\n" +
		"RUN apt-get install -y curl\n" + // unpinned - S011 really does fire here
		"USER app\n"
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}

	resetFlags(t)
	rootCmd.SetArgs([]string{"--no-explain", "--fail-on", "never", path})
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&bytes.Buffer{})

	if got := Execute(); got != 0 {
		t.Fatalf("Execute() = %d, want 0; output:\n%s", got, out.String())
	}
	if bytes.Contains(out.Bytes(), []byte("U001")) {
		t.Errorf("did not expect a U001 finding when the suppression was actually used, got:\n%s", out.String())
	}
	if bytes.Contains(out.Bytes(), []byte("S011")) {
		t.Errorf("expected S011 itself to stay suppressed, got:\n%s", out.String())
	}
}

func TestExecuteWriteBaselineThenBaselineSuppressesKnownFindings(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Dockerfile")
	// No USER set, so S001 (Error) fires - proving --write-baseline forces
	// exit 0 despite an Error-level finding, not just coincidentally
	// passing because nothing serious was present.
	src := "FROM ubuntu:22.04\nRUN apt-get install -y curl\n"
	if err := os.WriteFile(path, []byte(src), 0o644); err != nil {
		t.Fatal(err)
	}
	baselinePath := filepath.Join(dir, "baseline.json")

	resetFlags(t)
	rootCmd.SetArgs([]string{"--no-explain", "--fail-on", "error", "--write-baseline", baselinePath, path})
	rootCmd.SetOut(&bytes.Buffer{})
	var writeStderr bytes.Buffer
	rootCmd.SetErr(&writeStderr)
	if got := Execute(); got != 0 {
		t.Fatalf("Execute() (write-baseline) = %d, want 0 even though S001 (Error) fires; stderr:\n%s", got, writeStderr.String())
	}
	if !bytes.Contains(writeStderr.Bytes(), []byte("Wrote baseline")) {
		t.Errorf("expected a baseline-written confirmation on stderr, got:\n%s", writeStderr.String())
	}
	if _, err := os.Stat(baselinePath); err != nil {
		t.Fatalf("expected a baseline file to be written: %v", err)
	}

	// Same file, unchanged - comparing against the baseline should report
	// nothing new, and --fail-on error should NOT gate even though S001
	// (Error), P002, and P008 are all still technically present.
	resetFlags(t)
	rootCmd.SetArgs([]string{"--no-explain", "--fail-on", "error", "--baseline", baselinePath, path})
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&bytes.Buffer{})
	if got := Execute(); got != 0 {
		t.Errorf("Execute() (baseline compare) = %d, want 0 for an unchanged file; output:\n%s", got, out.String())
	}
	if bytes.Contains(out.Bytes(), []byte("S001")) || bytes.Contains(out.Bytes(), []byte("P002")) || bytes.Contains(out.Bytes(), []byte("P008")) {
		t.Errorf("expected already-baselined findings to be hidden, got:\n%s", out.String())
	}
}

func TestExecuteBaselineReportsGenuinelyNewFinding(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Dockerfile")
	if err := os.WriteFile(path, []byte("FROM ubuntu:22.04\nUSER app\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	baselinePath := filepath.Join(dir, "baseline.json")

	resetFlags(t)
	rootCmd.SetArgs([]string{"--no-explain", "--fail-on", "never", "--write-baseline", baselinePath, path})
	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetErr(&bytes.Buffer{})
	if got := Execute(); got != 0 {
		t.Fatalf("Execute() (write-baseline) = %d, want 0", got)
	}

	// Now introduce a genuinely new issue not present when the baseline was written.
	if err := os.WriteFile(path, []byte("FROM ubuntu:22.04\nRUN apt-get install -y curl\nUSER app\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	resetFlags(t)
	rootCmd.SetArgs([]string{"--no-explain", "--fail-on", "warning", "--baseline", baselinePath, path})
	var out bytes.Buffer
	rootCmd.SetOut(&out)
	rootCmd.SetErr(&bytes.Buffer{})
	if got := Execute(); got != 1 {
		t.Fatalf("Execute() = %d, want 1 (a genuinely new warning-level finding should gate); output:\n%s", got, out.String())
	}
	if !bytes.Contains(out.Bytes(), []byte("P002")) {
		t.Errorf("expected the new P002 finding to be reported, got:\n%s", out.String())
	}
}

func TestExecuteRejectsBaselineAndWriteBaselineTogether(t *testing.T) {
	resetFlags(t)
	rootCmd.SetArgs([]string{"--baseline", "a.json", "--write-baseline", "b.json", "Dockerfile"})
	rootCmd.SetOut(&bytes.Buffer{})
	var stderr bytes.Buffer
	rootCmd.SetErr(&stderr)

	realStderr := os.Stderr
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = devNull
	got := Execute()
	os.Stderr = realStderr
	devNull.Close()

	if got != 2 {
		t.Errorf("Execute() = %d, want 2 (tool error) when --baseline and --write-baseline are combined", got)
	}
}

func TestExecuteMissingBaselineFileIsAToolError(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Dockerfile")
	if err := os.WriteFile(path, []byte("FROM alpine\nUSER app\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	resetFlags(t)
	rootCmd.SetArgs([]string{"--baseline", filepath.Join(dir, "does-not-exist.json"), path})
	rootCmd.SetOut(&bytes.Buffer{})
	rootCmd.SetErr(&bytes.Buffer{})

	realStderr := os.Stderr
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = devNull
	got := Execute()
	os.Stderr = realStderr
	devNull.Close()

	if got != 2 {
		t.Errorf("Execute() = %d, want 2 for a missing --baseline file", got)
	}
}

func TestExecuteExitCodes(t *testing.T) {
	repoRoot, err := filepath.Abs("../..")
	if err != nil {
		t.Fatal(err)
	}
	clean := filepath.Join(repoRoot, "testdata", "dockerfiles", "simple.Dockerfile")
	withError := filepath.Join(repoRoot, "testdata", "dockerfiles", "insecure.Dockerfile")

	tests := []struct {
		name string
		args []string
		want int
	}{
		{"clean file, default fail-on", []string{clean}, 0},
		{"file with an S001 error, default fail-on", []string{withError}, 1},
		{"file with an error, fail-on never", []string{"--fail-on", "never", withError}, 0},
		{"missing file is a tool error", []string{filepath.Join(repoRoot, "testdata", "dockerfiles", "does-not-exist.Dockerfile")}, 2},
		{"invalid --fail-on value is a tool error", []string{"--fail-on", "bogus", clean}, 2},
		{"invalid --severity value is a tool error", []string{"--severity", "bogus", clean}, 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			resetFlags(t)
			rootCmd.SetArgs(append([]string{"--no-explain"}, tt.args...))
			rootCmd.SetOut(&bytes.Buffer{})
			rootCmd.SetErr(&bytes.Buffer{})

			// Execute() prints tool errors to os.Stderr directly; suppress
			// that noise in test output without affecting the assertion.
			realStderr := os.Stderr
			devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
			if err != nil {
				t.Fatal(err)
			}
			os.Stderr = devNull
			got := Execute()
			os.Stderr = realStderr
			devNull.Close()

			if got != tt.want {
				t.Errorf("Execute() = %d, want %d", got, tt.want)
			}
		})
	}
}
