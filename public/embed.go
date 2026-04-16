package public

import (
	"embed"
	"io/fs"
)

//go:embed all:*.html all:*.js all:*.css all:*.svg
var publicFS embed.FS

// FS returns the embedded public filesystem
func FS() (fs.FS, error) {
	return publicFS, nil
}
