package json

import (
	"encoding/json"
	"io"

	"github.com/onatribar/dockscribe/pkg/report"
)

type Renderer struct {
	Out io.Writer
}

func New(out io.Writer) *Renderer {
	return &Renderer{Out: out}
}

func (r *Renderer) Render(rep report.Report) error {
	enc := json.NewEncoder(r.Out)
	enc.SetIndent("", "  ")
	return enc.Encode(rep)
}
