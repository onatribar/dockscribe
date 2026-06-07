package renderer

import "github.com/onatribar/dockscribe/pkg/report"

type Renderer interface {
	Render(r report.Report) error
}
