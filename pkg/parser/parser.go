// Package parser defines the interfaces file-type-specific parsers implement.
package parser

type Parser interface {
	CanParse(filename string) bool
	Parse(src []byte) (ParsedFile, error)
}

// Each file type embeds this and adds its own fields.
type ParsedFile interface {
	FileType() string
	RawLines() []string
}
