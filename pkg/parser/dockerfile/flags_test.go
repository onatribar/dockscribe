package dockerfile

import (
	"reflect"
	"testing"
)

func TestSplitFlags(t *testing.T) {
	tests := []struct {
		name           string
		args           string
		wantFlags      map[string]string
		wantPositional []string
	}{
		{
			name:           "no flags",
			args:           "package.json package-lock.json ./",
			wantFlags:      map[string]string{},
			wantPositional: []string{"package.json", "package-lock.json", "./"},
		},
		{
			name:           "chown and from",
			args:           "--chown=app:app --from=builder /src/app /app",
			wantFlags:      map[string]string{"--chown": "app:app", "--from": "builder"},
			wantPositional: []string{"/src/app", "/app"},
		},
		{
			name:           "bare flag no value",
			args:           "--link src dst",
			wantFlags:      map[string]string{"--link": ""},
			wantPositional: []string{"src", "dst"},
		},
		{
			name:           "empty",
			args:           "",
			wantFlags:      map[string]string{},
			wantPositional: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			flags, positional := SplitFlags(tt.args)
			if !reflect.DeepEqual(flags, tt.wantFlags) {
				t.Errorf("flags = %#v, want %#v", flags, tt.wantFlags)
			}
			if !reflect.DeepEqual(positional, tt.wantPositional) {
				t.Errorf("positional = %#v, want %#v", positional, tt.wantPositional)
			}
		})
	}
}

func TestStripLeadingRunFlags(t *testing.T) {
	tests := []struct {
		name string
		args string
		want string
	}{
		{"no flags", "npm ci", "npm ci"},
		{"single mount flag", "--mount=type=cache,target=/root/.npm npm ci", "npm ci"},
		{"multiple leading flags", "--mount=type=cache,target=/x --network=none apt-get update", "apt-get update"},
		{"does not strip flags belonging to the command itself", "pip install --no-cache-dir -r requirements.txt", "pip install --no-cache-dir -r requirements.txt"},
		{"bare flag with no value", "--network=none echo hi", "echo hi"},
		{
			name: "preserves internal newlines (heredoc body)",
			args: "apt-get update\napt-get install -y curl",
			want: "apt-get update\napt-get install -y curl",
		},
		{
			name: "strips leading flags without disturbing a multi-line body",
			args: "--mount=type=cache,target=/x apt-get update\napt-get install -y curl",
			want: "apt-get update\napt-get install -y curl",
		},
		{"empty", "", ""},
		{"only flags", "--mount=type=cache,target=/x", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := StripLeadingRunFlags(tt.args); got != tt.want {
				t.Errorf("StripLeadingRunFlags(%q) = %q, want %q", tt.args, got, tt.want)
			}
		})
	}
}
