// Package sbom generates a CycloneDX 1.5 Software Bill of Materials
// deterministically from the dependency manifests in a repo — no model, no
// network. Parity with the Python sbom.py: same ecosystems, purl types,
// property key, vendored-dir skipping, and deterministic ordering.
package sbom

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
)

const (
	SBOMFile   = "sbom.cdx.json"
	CDXVersion = "1.5"
)

var skipDirs = map[string]bool{
	"node_modules": true, "vendor": true, ".git": true, ".venv": true, "venv": true,
	"env": true, "__pycache__": true, "site-packages": true, "dist": true,
	"build": true, ".tox": true, ".mypy_cache": true, "bower_components": true, "target": true,
}

// purlType maps ecosystem -> purl type (identity map, kept explicit for parity).
var purlType = map[string]string{
	"pypi": "pypi", "npm": "npm", "golang": "golang", "maven": "maven",
	"gem": "gem", "cargo": "cargo", "composer": "composer",
}

// Component is one dependency.
type Component struct {
	Name      string
	Version   string
	Group     string
	Ecosystem string
	License   string
}

// CDX types (the subset vhlocal emits).
type cdxDoc struct {
	BOMFormat   string      `json:"bomFormat"`
	SpecVersion string      `json:"specVersion"`
	Version     int         `json:"version"`
	Metadata    cdxMetadata `json:"metadata"`
	Components  []cdxComp   `json:"components"`
}
type cdxMetadata struct {
	Tools     []cdxTool   `json:"tools"`
	Component cdxMetaComp `json:"component"`
	Timestamp string      `json:"timestamp,omitempty"`
}
type cdxTool struct {
	Vendor string `json:"vendor"`
	Name   string `json:"name"`
}
type cdxMetaComp struct {
	Type string `json:"type"`
	Name string `json:"name"`
}
type cdxComp struct {
	Type       string        `json:"type"`
	Name       string        `json:"name"`
	Group      string        `json:"group,omitempty"`
	Version    string        `json:"version,omitempty"`
	Purl       string        `json:"purl"`
	Properties []cdxProperty `json:"properties"`
	Licenses   []cdxLicense  `json:"licenses,omitempty"`
}
type cdxProperty struct {
	Name  string `json:"name"`
	Value string `json:"value"`
}
type cdxLicense struct {
	License cdxLicenseName `json:"license"`
}
type cdxLicenseName struct {
	Name string `json:"name"`
}

func purl(eco, group, name, version string) string {
	t := purlType[eco]
	if t == "" {
		t = eco
	}
	s := "pkg:" + t + "/"
	if group != "" {
		s += group + "/"
	}
	s += name
	if version != "" {
		s += "@" + version
	}
	return s
}

// Collect parses all supported manifests under repo and returns deduplicated,
// deterministically ordered components.
func Collect(repo string) []Component {
	seen := map[string]bool{}
	var comps []Component
	add := func(c Component) {
		key := c.Ecosystem + "|" + c.Group + "|" + c.Name + "|" + c.Version
		if seen[key] {
			return
		}
		seen[key] = true
		comps = append(comps, c)
	}
	for _, f := range findManifests(repo) {
		for _, c := range parseManifest(f) {
			add(c)
		}
	}
	sort.Slice(comps, func(i, j int) bool {
		if comps[i].Ecosystem != comps[j].Ecosystem {
			return comps[i].Ecosystem < comps[j].Ecosystem
		}
		if strings.ToLower(comps[i].Name) != strings.ToLower(comps[j].Name) {
			return strings.ToLower(comps[i].Name) < strings.ToLower(comps[j].Name)
		}
		return comps[i].Version < comps[j].Version
	})
	return comps
}

// Build returns the CycloneDX document for a repo.
func Build(repo, timestamp string) cdxDoc {
	name := filepath.Base(repo)
	if name == "" || name == "." || name == string(os.PathSeparator) {
		name = "application"
	}
	doc := cdxDoc{
		BOMFormat: "CycloneDX", SpecVersion: CDXVersion, Version: 1,
		Metadata: cdxMetadata{
			Tools:     []cdxTool{{Vendor: "vhlocal", Name: "sbom"}},
			Component: cdxMetaComp{Type: "application", Name: name},
			Timestamp: timestamp,
		},
		Components: []cdxComp{},
	}
	for _, c := range Collect(repo) {
		comp := cdxComp{
			Type: "library", Name: c.Name, Group: c.Group, Version: c.Version,
			Purl:       purl(c.Ecosystem, c.Group, c.Name, c.Version),
			Properties: []cdxProperty{{Name: "vhlocal:ecosystem", Value: c.Ecosystem}},
		}
		if c.License != "" {
			comp.Licenses = []cdxLicense{{License: cdxLicenseName{Name: c.License}}}
		}
		doc.Components = append(doc.Components, comp)
	}
	return doc
}

// Write generates and writes sbom.cdx.json into resultsDir, returning its path.
func Write(repo, resultsDir, timestamp string) (string, error) {
	doc := Build(repo, timestamp)
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return "", err
	}
	out := filepath.Join(resultsDir, SBOMFile)
	return out, os.WriteFile(out, b, 0o644)
}

// WriteTo generates the SBOM for repo and writes it to an exact output path
// (used by the standalone `vhlocal sbom` command; default ./sbom.cdx.json).
func WriteTo(repo, outPath, timestamp string) error {
	doc := Build(repo, timestamp)
	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(outPath, b, 0o644)
}

// Summary is the object embedded in findings.json application_intelligence.sbom.
type Summary struct {
	Total       int              `json:"total"`
	ByEcosystem map[string]int   `json:"by_ecosystem"`
	Components  []map[string]any `json:"components"`
}

// Summarize builds the report summary for a repo.
func Summarize(repo string) Summary {
	s := Summary{ByEcosystem: map[string]int{}, Components: []map[string]any{}}
	for _, c := range Collect(repo) {
		s.Total++
		s.ByEcosystem[c.Ecosystem]++
		s.Components = append(s.Components, map[string]any{
			"name": c.Name, "version": c.Version, "ecosystem": c.Ecosystem,
			"license": c.License, "group": c.Group,
		})
	}
	return s
}

// --- manifest discovery + parsing ---

var manifestNames = map[string]string{
	"requirements.txt": "pypi", "pyproject.toml": "pypi", "package.json": "npm",
	"go.mod": "golang", "pom.xml": "maven", "Gemfile.lock": "gem",
	"Cargo.toml": "cargo", "composer.json": "composer",
}

func findManifests(repo string) []string {
	var out []string
	filepath.WalkDir(repo, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			if skipDirs[d.Name()] {
				return filepath.SkipDir
			}
			return nil
		}
		base := d.Name()
		if _, ok := manifestNames[base]; ok {
			out = append(out, p)
		} else if strings.HasPrefix(base, "requirements") && strings.HasSuffix(base, ".txt") {
			out = append(out, p)
		}
		return nil
	})
	sort.Strings(out)
	return out
}

func parseManifest(path string) []Component {
	base := filepath.Base(path)
	eco := manifestNames[base]
	if eco == "" && strings.HasPrefix(base, "requirements") {
		eco = "pypi"
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil
	}
	switch eco {
	case "pypi":
		if base == "pyproject.toml" {
			return parsePyproject(string(data))
		}
		return parseRequirements(string(data))
	case "npm":
		return parsePackageJSON(data)
	case "golang":
		return parseGoMod(string(data))
	case "cargo":
		return parseCargo(string(data))
	default:
		return nil // maven/gem/composer parsers deferred; ecosystem recognized
	}
}

var reReqLine = regexp.MustCompile(`^\s*([A-Za-z0-9._-]+)\s*(?:[<>=!~]=?\s*([0-9][A-Za-z0-9._*-]*))?`)

func parseRequirements(s string) []Component {
	var out []Component
	for _, ln := range strings.Split(s, "\n") {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "#") || strings.HasPrefix(ln, "-") {
			continue
		}
		if m := reReqLine.FindStringSubmatch(ln); m != nil && m[1] != "" {
			out = append(out, Component{Name: m[1], Version: m[2], Ecosystem: "pypi"})
		}
	}
	return out
}

var rePyprojDep = regexp.MustCompile(`["']([A-Za-z0-9._-]+)\s*(?:[<>=!~]=?\s*([0-9][A-Za-z0-9._*-]*))?["']`)

func parsePyproject(s string) []Component {
	var out []Component
	inDeps := false
	for _, ln := range strings.Split(s, "\n") {
		t := strings.TrimSpace(ln)
		if strings.Contains(t, "dependencies") && strings.Contains(t, "[") {
			inDeps = true
		}
		if inDeps {
			if m := rePyprojDep.FindStringSubmatch(t); m != nil && m[1] != "python" {
				out = append(out, Component{Name: m[1], Version: m[2], Ecosystem: "pypi"})
			}
			if strings.Contains(t, "]") {
				inDeps = false
			}
		}
	}
	return out
}

func parsePackageJSON(data []byte) []Component {
	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
		PeerDeps        map[string]string `json:"peerDependencies"`
	}
	if json.Unmarshal(data, &pkg) != nil {
		return nil
	}
	var out []Component
	for _, m := range []map[string]string{pkg.Dependencies, pkg.DevDependencies, pkg.PeerDeps} {
		for name, ver := range m {
			out = append(out, Component{Name: name, Version: strings.TrimLeft(ver, "^~"), Ecosystem: "npm"})
		}
	}
	return out
}

var reGoDep = regexp.MustCompile(`^\s*([a-zA-Z0-9./_-]+)\s+(v[0-9][^\s]*)`)

func parseGoMod(s string) []Component {
	var out []Component
	for _, ln := range strings.Split(s, "\n") {
		t := strings.TrimSpace(ln)
		if strings.HasPrefix(t, "module ") || strings.HasPrefix(t, "go ") || t == "require (" || t == ")" {
			continue
		}
		t = strings.TrimPrefix(t, "require ")
		if m := reGoDep.FindStringSubmatch(t); m != nil {
			out = append(out, Component{Name: m[1], Version: m[2], Ecosystem: "golang"})
		}
	}
	return out
}

var reCargoDep = regexp.MustCompile(`^\s*([A-Za-z0-9._-]+)\s*=\s*(?:"([^"]+)"|\{[^}]*version\s*=\s*"([^"]+)")`)

func parseCargo(s string) []Component {
	var out []Component
	inDeps := false
	for _, ln := range strings.Split(s, "\n") {
		t := strings.TrimSpace(ln)
		if strings.HasPrefix(t, "[") {
			inDeps = strings.Contains(t, "dependencies")
			continue
		}
		if inDeps {
			if m := reCargoDep.FindStringSubmatch(t); m != nil {
				ver := m[2]
				if ver == "" {
					ver = m[3]
				}
				out = append(out, Component{Name: m[1], Version: ver, Ecosystem: "cargo"})
			}
		}
	}
	return out
}
