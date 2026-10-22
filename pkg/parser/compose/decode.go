package compose

import "gopkg.in/yaml.v3"

func pairs(n *yaml.Node) func(yield func(key, value *yaml.Node) bool) {
	return func(yield func(key, value *yaml.Node) bool) {
		if n == nil || n.Kind != yaml.MappingNode {
			return
		}
		for i := 0; i+1 < len(n.Content); i += 2 {
			if !yield(n.Content[i], resolveAlias(n.Content[i+1])) {
				return
			}
		}
	}
}

func resolveAlias(n *yaml.Node) *yaml.Node {
	for i := 0; i < 100 && n != nil && n.Kind == yaml.AliasNode; i++ {
		n = n.Alias
	}
	return n
}

func scalarString(n *yaml.Node) string {
	if n == nil || n.Kind != yaml.ScalarNode {
		return ""
	}
	return n.Value
}

func scalarBool(n *yaml.Node) bool {
	var b bool
	if n == nil || n.Kind != yaml.ScalarNode {
		return false
	}
	_ = n.Decode(&b)
	return b
}

func stringList(n *yaml.Node) []string {
	if n == nil || n.Kind != yaml.SequenceNode {
		return nil
	}
	var out []string
	for _, raw := range n.Content {
		item := resolveAlias(raw)
		if item.Kind == yaml.ScalarNode {
			out = append(out, item.Value)
		}
	}
	return out
}

func environment(n *yaml.Node) map[string]string {
	if n == nil {
		return nil
	}
	out := map[string]string{}
	switch n.Kind {
	case yaml.MappingNode:
		for k, v := range pairs(n) {
			out[k.Value] = scalarString(v)
		}
	case yaml.SequenceNode:
		for _, raw := range n.Content {
			item := resolveAlias(raw)
			if item.Kind != yaml.ScalarNode {
				continue
			}
			key, value := item.Value, ""
			for i := 0; i < len(item.Value); i++ {
				if item.Value[i] == '=' {
					key, value = item.Value[:i], item.Value[i+1:]
					break
				}
			}
			out[key] = value
		}
	}
	return out
}

func build(n *yaml.Node) *BuildConfig {
	if n == nil {
		return nil
	}
	switch n.Kind {
	case yaml.ScalarNode:
		return &BuildConfig{Context: n.Value, Dockerfile: "Dockerfile"}
	case yaml.MappingNode:
		b := &BuildConfig{Dockerfile: "Dockerfile"}
		for k, v := range pairs(n) {
			switch k.Value {
			case "context":
				b.Context = scalarString(v)
			case "dockerfile":
				b.Dockerfile = scalarString(v)
			case "target":
				b.Target = scalarString(v)
			}
		}
		return b
	default:
		return nil
	}
}

func volumes(n *yaml.Node) []VolumeMount {
	if n == nil || n.Kind != yaml.SequenceNode {
		return nil
	}
	var out []VolumeMount
	for _, raw := range n.Content {
		item := resolveAlias(raw)
		switch item.Kind {
		case yaml.ScalarNode:
			out = append(out, parseShortVolume(item.Value))
		case yaml.MappingNode:
			var v VolumeMount
			for k, val := range pairs(item) {
				switch k.Value {
				case "source":
					v.Source = scalarString(val)
				case "target":
					v.Target = scalarString(val)
				}
			}
			out = append(out, v)
		}
	}
	return out
}

func parseShortVolume(raw string) VolumeMount {
	parts := splitN(raw, ':', 3)
	switch len(parts) {
	case 1:
		return VolumeMount{Target: parts[0]}
	default:
		return VolumeMount{Source: parts[0], Target: parts[1]}
	}
}

func splitN(s string, sep byte, n int) []string {
	var out []string
	start := 0
	for i := 0; i < len(s) && len(out) < n-1; i++ {
		if s[i] == sep {
			out = append(out, s[start:i])
			start = i + 1
		}
	}
	return append(out, s[start:])
}

func hasResourceLimits(serviceNode *yaml.Node) bool {
	for k, v := range pairs(serviceNode) {
		switch k.Value {
		case "mem_limit", "cpus", "cpu_shares", "mem_reservation":
			return true
		case "deploy":
			for dk, dv := range pairs(v) {
				if dk.Value != "resources" {
					continue
				}
				for rk, rv := range pairs(dv) {
					if rk.Value == "limits" && rv.Kind == yaml.MappingNode && len(rv.Content) > 0 {
						return true
					}
				}
			}
		}
	}
	return false
}
