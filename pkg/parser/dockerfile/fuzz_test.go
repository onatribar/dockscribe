package dockerfile

import (
	"os"
	"path/filepath"
	"testing"
)

// feed of arbitrary byte sequences through the real tokenizer
func FuzzParse(f *testing.F) {
	seeds, err := filepath.Glob("../../../testdata/dockerfiles/*.Dockerfile")
	if err == nil {
		for _, path := range seeds {
			if content, err := os.ReadFile(path); err == nil {
				f.Add(content)
			}
		}
	}

	// some hand-picked edge cases the tokenizer has specific handling for
	// worth seeding explicitly even though the corpus above should already exercise most of them
	edgeCases := []string{
		"",
		"FROM",
		"FROM \n",
		"RUN <<EOF\n",
		"RUN <<EOF\necho hi\n",
		"RUN <<\nEOF\n",
		"CMD [\n",
		"CMD [[[[\n",
		"CMD ]]]]\n",
		"FROM alpine\\",
		"FROM --platform=\nalpine\n",
		"FROM alpine AS\n",
		"\x00\x01\x02FROM alpine\n",
		"FROM " + string(make([]byte, 10000)),
	}

	for _, s := range edgeCases {
		f.Add([]byte(s))
	}

	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = New().Parse(data)
	})
}
