package dockerfile

import "strings"

// separate leading "--flag"/"--flag=value" tokens from positional arguments
// e.g. "--chown=app:app /src/app /app" -> ({"--chown": "app:app"}, ["/src/app", "/app"])
func SplitFlags(args string) (flags map[string]string, positional []string) {
	flags = map[string]string{}
	for _, field := range strings.Fields(args) {
		if !strings.HasPrefix(field, "--") {
			positional = append(positional, field)
			continue
		}
		if i := strings.IndexByte(field, '='); i >= 0 {
			flags[field[:i]] = field[i+1:]
		} else {
			flags[field] = ""
		}
	}
	return flags, positional
}

// removes leading BuildKit RUN option flags (--mount, --network, ...) and returns the shell command verbatim
// a flag belonging to the command itself (e.g. `pip install --no-cache-dir`) is left alone since it isn't at the front.
func StripLeadingRunFlags(args string) string {
	rest := args
	for {
		trimmed := strings.TrimLeft(rest, " \t")
		if !strings.HasPrefix(trimmed, "--") {
			return trimmed
		}

		end := strings.IndexAny(trimmed, " \t\n")
		if end == -1 {
			return ""
		}
		rest = trimmed[end:]
	}
}
