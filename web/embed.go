// Package web embeds the standalone, browser-local verification interface.
package web

import "embed"

// Assets includes the WASM binary after make web. Generated assets are ignored
// by Git; make build always generates them before embedding the native CLI.
//
//go:embed static
var Assets embed.FS
