// Package parser defines the interfaces that file-type-specific parsers
// implement to turn raw file bytes into a structured representation.
package parser

// Parser converts raw file bytes into a structured representation.
type Parser interface {
	CanParse(filename string) bool
	Parse(src []byte) (ParsedFile, error)
}

// ParsedFile is the structured output of a Parser. Each file type embeds
// this and adds its own fields.
type ParsedFile interface {
	FileType() string
	RawLines() []string
}
