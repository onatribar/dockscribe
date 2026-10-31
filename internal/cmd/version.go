package cmd

import "runtime/debug"

// Bump by hand at release time; combined at runtime with VCS info Go
// stamps in automatically - no -ldflags needed.
const version = "0.1.0"

func fullVersion() string {
	v := version
	info, ok := debug.ReadBuildInfo()
	if !ok {
		return v
	}

	var revision string
	var dirty bool
	for _, s := range info.Settings {
		switch s.Key {
		case "vcs.revision":
			revision = s.Value
		case "vcs.modified":
			dirty = s.Value == "true"
		}
	}
	if revision == "" {
		return v
	}
	if len(revision) > 12 {
		revision = revision[:12]
	}
	v += " (" + revision
	if dirty {
		v += ", modified"
	}
	v += ")"
	return v
}
