package compose

import (
	"os"
	"path/filepath"
	"testing"
)

func FuzzParse(f *testing.F) {
	seeds, err := filepath.Glob("../../../testdata/compose/*.yml")
	if err == nil {
		for _, path := range seeds {
			if content, err := os.ReadFile(path); err == nil {
				f.Add(content)
			}
		}
	}
	if content, err := os.ReadFile("../../../testdata/compose/build-reference/docker-compose.yml"); err == nil {
		f.Add(content)
	}

	edgeCases := []string{
		"",
		"services:\n",
		"services:\n  a:\n",
		"services: []\n",
		"services: not-a-mapping\n",
		"- a\n- b\n",
		"a: {b: {c: {d: {e: x}}}}\n",
		"services:\n  a:\n    volumes:\n      - \":::\"\n",
		"services:\n  a:\n    environment:\n      - \"=noname\"\n",
		"services:\n  a:\n    build: {}\n",
		"services:\n  a:\n    depends_on: {}\n",
		"&anchor\nservices: *anchor\n",
		"services: {a: {b: *undefined}}\n",
		"\x00\x01\x02services:\n",
	}
	for _, s := range edgeCases {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = New().Parse(data)
	})
}
