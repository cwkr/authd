package assets

import "embed"

//go:embed favicon.ico *.png *.css scripts/*.js
var StaticFiles embed.FS
