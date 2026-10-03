package server

import (
	"crypto/sha256"
	"encoding/hex"
	"io/fs"
	"os"
	"sort"
	"sync"
	"time"

	vhlocal "vhlocal"
)

// BuildIdentity is what /api/config reports so a browser validation run can
// record exactly which binary and embedded UI it exercised (feature 014, SC-012).
// The assets hash is computed once over the embedded web FS (every file, sorted by
// path, path+content), so two binaries with identical UI bytes agree and a stale
// `npm run build` is visible as a different hash.
type BuildIdentity struct {
	Version            string `json:"version"`
	EmbeddedAssetsHash string `json:"embedded_assets_hash"`
	BuiltAt            string `json:"built_at"`
	// BuiltAtSource says where built_at came from: "ldflags" when stamped at
	// build time, "executable_mtime" as the honest fallback, "unknown" otherwise.
	BuiltAtSource string `json:"built_at_source"`
}

var (
	buildOnce sync.Once
	buildID   BuildIdentity
)

// buildIdentity returns the cached identity for this process.
func (s *Server) buildIdentity() BuildIdentity {
	buildOnce.Do(func() {
		buildID = computeBuildIdentity(s.cfg.WebFS, s.cfg.Version)
	})
	return buildID
}

func computeBuildIdentity(web fs.FS, version string) BuildIdentity {
	if version == "" {
		version = vhlocal.Version
	}
	id := BuildIdentity{Version: version, EmbeddedAssetsHash: hashFS(web)}
	switch {
	case vhlocal.BuiltAt != "":
		id.BuiltAt, id.BuiltAtSource = vhlocal.BuiltAt, "ldflags"
	default:
		if exe, err := os.Executable(); err == nil {
			if fi, err := os.Stat(exe); err == nil {
				id.BuiltAt, id.BuiltAtSource = fi.ModTime().UTC().Format(time.RFC3339), "executable_mtime"
				return id
			}
		}
		id.BuiltAtSource = "unknown"
	}
	return id
}

// hashFS digests every regular file under the FS in path order. An absent FS
// hashes to "none" so the identity is still truthful for a UI-less server.
func hashFS(web fs.FS) string {
	if web == nil {
		return "none"
	}
	var paths []string
	_ = fs.WalkDir(web, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		paths = append(paths, p)
		return nil
	})
	sort.Strings(paths)
	h := sha256.New()
	for _, p := range paths {
		b, err := fs.ReadFile(web, p)
		if err != nil {
			continue
		}
		h.Write([]byte(p))
		h.Write([]byte{0})
		h.Write(b)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}
