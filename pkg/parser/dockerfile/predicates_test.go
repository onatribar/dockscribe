package dockerfile

import "testing"

func TestIsURL(t *testing.T) {
	tests := []struct {
		s    string
		want bool
	}{
		{"https://example.com/x.sh", true},
		{"http://example.com/x.sh", true},
		{"./local/path", false},
		{"ftp://example.com/x.sh", false},
		{"", false},
	}
	for _, tt := range tests {
		if got := IsURL(tt.s); got != tt.want {
			t.Errorf("IsURL(%q) = %v, want %v", tt.s, got, tt.want)
		}
	}
}

func TestIsBroadCopySource(t *testing.T) {
	tests := []struct {
		s    string
		want bool
	}{
		{".", true},
		{"./", true},
		{"*", true},
		{"/", true},
		{"package.json", false},
		{"./src", false},
		{"/app", false},
	}

	for _, tt := range tests {
		if got := IsBroadCopySource(tt.s); got != tt.want {
			t.Errorf("IsBroadCopySource(%q) = %v, want %v", tt.s, got, tt.want)
		}
	}
}

func TestIsRootUser(t *testing.T) {
	tests := []struct {
		user string
		want bool
	}{
		{"", true},
		{"root", true},
		{"ROOT", true},
		{"0", true},
		{"root:root", true},
		{"0:0", true},
		{"app", false},
		{"1000", false},
		{"app:app", false},
		{"  root  ", true},
	}

	for _, tt := range tests {
		if got := IsRootUser(tt.user); got != tt.want {
			t.Errorf("IsRootUser(%q) = %v, want %v", tt.user, got, tt.want)
		}
	}
}
