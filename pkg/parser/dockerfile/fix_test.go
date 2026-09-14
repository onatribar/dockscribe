package dockerfile

import "testing"

func TestFixPackageCacheApt(t *testing.T) {
	cmd, args, ok := FixInstruction("RUN", "apt-get update && apt-get install -y curl", "P002")
	if !ok {
		t.Fatal("expected a fix")
	}
	if cmd != "RUN" {
		t.Errorf("cmd = %q, want RUN", cmd)
	}
	want := "apt-get update && apt-get install -y curl && rm -rf /var/lib/apt/lists/*"
	if args != want {
		t.Errorf("args = %q, want %q", args, want)
	}
}

func TestFixPackageCacheApk(t *testing.T) {
	_, args, ok := FixInstruction("RUN", "apk add curl", "P002")
	if !ok {
		t.Fatal("expected a fix")
	}
	want := "apk add curl && rm -rf /var/cache/apk/*"
	if args != want {
		t.Errorf("args = %q, want %q", args, want)
	}
}

func TestFixPackageCacheYum(t *testing.T) {
	_, args, ok := FixInstruction("RUN", "yum install -y curl", "P002")
	if !ok {
		t.Fatal("expected a fix")
	}
	want := "yum install -y curl && yum clean all"
	if args != want {
		t.Errorf("args = %q, want %q", args, want)
	}
}

func TestFixPackageCacheDnf(t *testing.T) {
	_, args, ok := FixInstruction("RUN", "dnf install -y curl", "P002")
	if !ok {
		t.Fatal("expected a fix")
	}
	want := "dnf install -y curl && dnf clean all"
	if args != want {
		t.Errorf("args = %q, want %q", args, want)
	}
}

func TestFixPackageCachePip(t *testing.T) {
	_, args, ok := FixInstruction("RUN", "pip install flask", "P002")
	if !ok {
		t.Fatal("expected a fix")
	}
	want := "pip install --no-cache-dir flask"
	if args != want {
		t.Errorf("args = %q, want %q", args, want)
	}
}

func TestFixPackageCachePip3(t *testing.T) {
	_, args, ok := FixInstruction("RUN", "pip3 install flask", "P002")
	if !ok {
		t.Fatal("expected a fix")
	}
	want := "pip3 install --no-cache-dir flask"
	if args != want {
		t.Errorf("args = %q, want %q", args, want)
	}
}

func TestFixPackageCacheNoMatch(t *testing.T) {
	if _, _, ok := FixInstruction("RUN", "echo hello", "P002"); ok {
		t.Error("did not expect a fix for a RUN with no package manager install")
	}
}

func TestFixPackageCachePreservesLeadingBuildKitFlag(t *testing.T) {
	_, args, ok := FixInstruction("RUN", "--mount=type=cache,target=/var/cache/apt apt-get install -y curl", "P002")
	if !ok {
		t.Fatal("expected a fix")
	}
	want := "--mount=type=cache,target=/var/cache/apt apt-get install -y curl && rm -rf /var/lib/apt/lists/*"
	if args != want {
		t.Errorf("args = %q, want %q", args, want)
	}
}

func TestFixAddToCopy(t *testing.T) {
	cmd, args, ok := FixInstruction("ADD", "./assets /app/assets", "P004")
	if !ok {
		t.Fatal("expected a fix")
	}
	if cmd != "COPY" {
		t.Errorf("cmd = %q, want COPY", cmd)
	}
	if args != "./assets /app/assets" {
		t.Errorf("args changed unexpectedly: %q", args)
	}
}

func TestFixAddToCopyOnlyAppliesToAdd(t *testing.T) {
	if _, _, ok := FixInstruction("COPY", "./assets /app/assets", "P004"); ok {
		t.Error("did not expect a P004 fix on an instruction that isn't ADD")
	}
}

func TestFixNoInstallRecommends(t *testing.T) {
	cmd, args, ok := FixInstruction("RUN", "apt-get install -y curl", "P008")
	if !ok {
		t.Fatal("expected a fix")
	}
	if cmd != "RUN" {
		t.Errorf("cmd = %q, want RUN", cmd)
	}
	want := "apt-get install --no-install-recommends -y curl"
	if args != want {
		t.Errorf("args = %q, want %q", args, want)
	}
}

func TestFixNoInstallRecommendsAlreadyPresent(t *testing.T) {
	if _, _, ok := FixInstruction("RUN", "apt-get install -y --no-install-recommends curl", "P008"); ok {
		t.Error("did not expect a fix when --no-install-recommends is already present")
	}
}

func TestFixNoInstallRecommendsNoAptInstall(t *testing.T) {
	if _, _, ok := FixInstruction("RUN", "pip install flask", "P008"); ok {
		t.Error("did not expect a P008 fix for a non-apt command")
	}
}

func TestFixUnknownRule(t *testing.T) {
	if _, _, ok := FixInstruction("RUN", "apt-get install -y curl", "S001"); ok {
		t.Error("did not expect a fix for a rule with no fixer")
	}
}

func TestIsFixableRule(t *testing.T) {
	for _, id := range []string{"P002", "P004", "P008"} {
		if !IsFixableRule(id) {
			t.Errorf("IsFixableRule(%q) = false, want true", id)
		}
	}
	for _, id := range []string{"S001", "P015", "S007", ""} {
		if IsFixableRule(id) {
			t.Errorf("IsFixableRule(%q) = true, want false", id)
		}
	}
}

func TestFixChaining(t *testing.T) {
	// Simulate a caller applying two fixes to the same line in sequence
	cmd, args, ok := FixInstruction("RUN", "apt-get install -y curl", "P002")
	if !ok {
		t.Fatal("expected P002 fix")
	}
	_, args, ok = FixInstruction(cmd, args, "P008")
	if !ok {
		t.Fatal("expected P008 fix to also apply")
	}
	want := "apt-get install --no-install-recommends -y curl && rm -rf /var/lib/apt/lists/*"
	if args != want {
		t.Errorf("chained args = %q, want %q", args, want)
	}
}
