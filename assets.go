// Package vhlocal (module root) carries the embedded assets that make the
// binary self-contained: the bundled scanning methodology (skill/) and the
// browser UI (vhlocal/web/, including the built React app/ bundle and the
// legacy/classic single-file HTML UIs).
//
// Build ordering: run `npm run build` in web-react/ (outputs to vhlocal/web/app)
// BEFORE `go build`, so the embed below captures the current UI assets. The
// legacy/classic HTML files and mermaid.min.js are committed and always present.
//
// go:embed cannot reference parent directories, so these directives live at the
// module root where skill/ and vhlocal/web/ are direct children.
package vhlocal

import "embed"

// SkillFS holds the bundled vulnhunt methodology: SKILL.md + phases/*.md.
// Overridable at runtime by --skill-dir pointing at a real directory.
//
//go:embed all:skill
var SkillFS embed.FS

// WebFS holds the browser UI served by the HTTP engine. `all:` includes files
// whose names begin with '.' or '_' (Vite emits some). The built app/ subtree
// is present only after `npm run build`; the directive still compiles without it.
//
//go:embed all:vhlocal/web
var WebFS embed.FS

// Version is stamped at build time via -ldflags "-X vhlocal.Version=...".
var Version = "dev"

// BuiltAt is stamped at build time via -ldflags "-X vhlocal.BuiltAt=<RFC3339>"; when
// empty the server falls back to the executable's modification time (feature 014,
// SC-012 build identity) and says so.
var BuiltAt = ""
