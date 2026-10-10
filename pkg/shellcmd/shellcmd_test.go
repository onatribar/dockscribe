package shellcmd

import "testing"

func TestPipeDetection(t *testing.T) {
	a, ok := Analyze(`curl -fsSL https://example.com/i.sh | bash`)
	if !ok {
		t.Fatal("expected script to parse")
	}
	if len(a.PipePairs) != 1 {
		t.Fatalf("expected 1 pipe pair, got %d: %+v", len(a.PipePairs), a.PipePairs)
	}
	if a.PipePairs[0].From.Name != "curl" || a.PipePairs[0].To.Name != "bash" {
		t.Errorf("pipe pair = %+v", a.PipePairs[0])
	}
}

func TestChainedPipeDetection(t *testing.T) {
	a, ok := Analyze(`curl -fsSL https://example.com/i.sh | tee x.sh | bash`)
	if !ok {
		t.Fatal("expected script to parse")
	}
	if len(a.PipePairs) != 2 {
		t.Fatalf("expected 2 pipe pairs for a 3-stage pipeline, got %d: %+v", len(a.PipePairs), a.PipePairs)
	}

	got := map[[2]string]bool{}
	for _, p := range a.PipePairs {
		got[[2]string{p.From.Name, p.To.Name}] = true
	}
	for _, want := range [][2]string{{"curl", "tee"}, {"tee", "bash"}} {
		if !got[want] {
			t.Errorf("missing pipe pair %v; got %+v", want, a.PipePairs)
		}
	}
}

func TestPipeInsideAndChain(t *testing.T) {
	a, ok := Analyze(`apt-get update && curl -fsSL https://x/i.sh | bash && echo done`)
	if !ok {
		t.Fatal("expected script to parse")
	}
	if len(a.PipePairs) != 1 {
		t.Fatalf("expected 1 pipe pair, got %d: %+v", len(a.PipePairs), a.PipePairs)
	}
	if !a.HasCommand("apt-get") || !a.HasCommand("echo") {
		t.Errorf("expected apt-get and echo to be captured as commands too, got %+v", a.Commands)
	}
}

func TestNoFalsePipeAcrossAndOr(t *testing.T) {
	// curl succeeds independently of bash here so this must NOT be flagged as a curl|bash pattern
	a, ok := Analyze(`curl -fsSL https://x/i.sh -o i.sh && bash i.sh`)
	if !ok {
		t.Fatal("expected script to parse")
	}
	if len(a.PipePairs) != 0 {
		t.Errorf("expected no pipe pairs, got %+v", a.PipePairs)
	}
}

func TestVarRefs(t *testing.T) {
	a, ok := Analyze(`echo "token is $TOKEN and ${OTHER}"`)
	if !ok {
		t.Fatal("expected script to parse")
	}
	if !a.RefersTo("TOKEN") || !a.RefersTo("OTHER") {
		t.Errorf("expected VarRefs to include TOKEN and OTHER, got %v", a.VarRefs)
	}
}

func TestVarRefInCommandArg(t *testing.T) {
	a, ok := Analyze(`curl -H "Authorization: Bearer $TOKEN" https://example.com`)
	if !ok {
		t.Fatal("expected script to parse")
	}
	if !a.RefersTo("TOKEN") {
		t.Errorf("expected TOKEN to be recorded as referenced, got %v", a.VarRefs)
	}
	found := false
	for _, c := range a.Commands {
		if c.Name == "curl" {
			found = true
			joined := c.Joined()
			if joined == "" {
				t.Errorf("expected curl command args to render, got empty")
			}
		}
	}
	if !found {
		t.Errorf("expected curl to be captured as a command, got %+v", a.Commands)
	}
}

func TestAssignmentPrefix(t *testing.T) {
	a, ok := Analyze(`CGO_ENABLED=0 GOOS=linux go build -o /out/app .`)
	if !ok {
		t.Fatal("expected script to parse")
	}
	if !a.HasCommand("go") {
		t.Fatalf("expected go to be captured as the command, got %+v", a.Commands)
	}
	var goCmd Command
	for _, c := range a.Commands {
		if c.Name == "go" {
			goCmd = c
		}
	}
	if goCmd.Assigns["CGO_ENABLED"] != "0" || goCmd.Assigns["GOOS"] != "linux" {
		t.Errorf("assigns = %+v", goCmd.Assigns)
	}
}

func TestSudoDetection(t *testing.T) {
	a, ok := Analyze(`sudo apt-get install -y curl`)
	if !ok {
		t.Fatal("expected script to parse")
	}
	if !a.HasCommand("sudo") {
		t.Errorf("expected sudo to be captured, got %+v", a.Commands)
	}
}

func TestMultipleStatementsSemicolon(t *testing.T) {
	a, ok := Analyze(`echo one; echo two; echo three`)
	if !ok {
		t.Fatal("expected script to parse")
	}
	count := 0
	for _, c := range a.Commands {
		if c.Name == "echo" {
			count++
		}
	}
	if count != 3 {
		t.Errorf("expected 3 echo commands, got %d: %+v", count, a.Commands)
	}
}

func TestWritesFromRedirect(t *testing.T) {
	a, ok := Analyze(`echo "$TOKEN" > /app/.env`)
	if !ok {
		t.Fatal("expected script to parse")
	}
	if !a.WritesTo("/app/.env") {
		t.Errorf("expected Writes to include /app/.env, got %v", a.Writes)
	}
}

func TestWritesFromAppendRedirect(t *testing.T) {
	a, ok := Analyze(`echo "$TOKEN" >> /app/.env`)
	if !ok {
		t.Fatal("expected script to parse")
	}
	if !a.WritesTo("/app/.env") {
		t.Errorf("expected Writes to include /app/.env, got %v", a.Writes)
	}
}

func TestWritesFromCpMvTee(t *testing.T) {
	a, ok := Analyze(`cp secret.pem /root/.ssh/secret.pem && mv x.txt /tmp/y.txt && echo hi | tee /var/log/hi.log`)
	if !ok {
		t.Fatal("expected script to parse")
	}
	for _, want := range []string{"/root/.ssh/secret.pem", "/tmp/y.txt", "/var/log/hi.log"} {
		if !a.WritesTo(want) {
			t.Errorf("expected Writes to include %q, got %v", want, a.Writes)
		}
	}
}

func TestWritesToDirectoryPrefix(t *testing.T) {
	a, ok := Analyze(`echo x > /root/.ssh/id_rsa`)
	if !ok {
		t.Fatal("expected script to parse")
	}
	if !a.WritesTo("/root/.ssh") {
		t.Errorf("expected WritesTo(/root/.ssh) to be true since a file underneath it was written")
	}
	if a.WritesTo("/root/.ssh/id_rsa/nope") {
		t.Errorf("did not expect WritesTo to match an unrelated deeper path")
	}
}

func TestRemovesPathExact(t *testing.T) {
	a, ok := Analyze(`rm /root/.ssh/id_rsa`)
	if !ok {
		t.Fatal("expected script to parse")
	}
	if !a.RemovesPath("/root/.ssh/id_rsa") {
		t.Error("expected RemovesPath to match the exact rm'd path")
	}
}

func TestRemovesPathViaDirectory(t *testing.T) {
	a, ok := Analyze(`rm -rf /root/.ssh`)
	if !ok {
		t.Fatal("expected script to parse")
	}
	if !a.RemovesPath("/root/.ssh/id_rsa") {
		t.Error("expected RemovesPath to match a file under an rm -rf'd directory")
	}
	if a.RemovesPath("/root/.ssh-backup/id_rsa") {
		t.Error("did not expect RemovesPath to match a sibling directory with a shared prefix")
	}
}

func TestRemovesPathViaTrailingGlob(t *testing.T) {
	a, ok := Analyze(`rm -rf /var/lib/apt/lists/*`)
	if !ok {
		t.Fatal("expected script to parse")
	}
	if !a.RemovesPath("/var/lib/apt/lists") {
		t.Error("expected RemovesPath to match a directory cleared via a trailing /* glob")
	}
}

func TestRemovesPathNoFalsePositive(t *testing.T) {
	a, ok := Analyze(`rm /tmp/scratch.txt`)
	if !ok {
		t.Fatal("expected script to parse")
	}
	if a.RemovesPath("/root/.ssh/id_rsa") {
		t.Error("did not expect an unrelated rm to match")
	}
}

func TestUnparseableFallsBackGracefully(t *testing.T) {
	if _, ok := Analyze(""); ok {
		t.Error("expected empty script to report ok=false")
	}
	_, _ = Analyze(`["not", "shell", "syntax"`)
}
