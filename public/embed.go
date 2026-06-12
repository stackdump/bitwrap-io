package public

import (
	"embed"
	"io/fs"
)

//go:embed all:*.html all:*.js all:*.mjs all:*.css all:*.svg all:*.wasm all:vendor
var publicFS embed.FS

// FS returns the embedded public filesystem
func FS() (fs.FS, error) {
	return publicFS, nil
}
