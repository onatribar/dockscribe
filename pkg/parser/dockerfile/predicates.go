package dockerfile

import "strings"

// whether s is a remote http(s) source, as used by ADD/COPY source classification
func IsURL(s string) bool {
	return strings.HasPrefix(s, "http://") || strings.HasPrefix(s, "https://")
}

// if (".", "./", "*", or "/") copies the whole build context or the whole other stage for "COPY --from=stage".
// sources are always relative to the context/stage root even with a leading slash
func IsBroadCopySource(s string) bool {
	return s == "." || s == "./" || s == "*" || s == "/"
}

// does USER's instruction value resolve to root?
// literal name "root, or uid 0"
func IsRootUser(user string) bool {
	u := strings.TrimSpace(user)
	if u == "" {
		return true
	}

	name := u
	if i := strings.IndexByte(u, ':'); i >= 0 {
		name = u[:i]
	}

	switch strings.ToLower(name) {
	case "root", "0":
		return true
	}

	return false
}
