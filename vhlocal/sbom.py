"""Software Bill of Materials — deterministic dependency inventory.

Parses the dependency manifests present in a repo across ecosystems and emits a
CycloneDX 1.5 SBOM (`sbom.cdx.json`) plus a summary for the report's Application
Intelligence section. No model, no network — just manifest parsing — so it is
reproducible and can run standalone on any repo. Stdlib only (Python 3.9: no
tomllib, so TOML manifests are parsed with targeted regex, not a full TOML lib).
"""

import json
import re
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Any, Callable, Dict, List, Optional

SBOM_FILE = "sbom.cdx.json"
CDX_VERSION = "1.5"

# Directories that hold vendored/third-party trees we don't want to walk.
_SKIP_DIRS = {"node_modules", "vendor", ".git", ".venv", "venv", "env",
              "__pycache__", "site-packages", "dist", "build", ".tox", ".mypy_cache",
              "bower_components", "target"}

_PURL_TYPE = {"pypi": "pypi", "npm": "npm", "golang": "golang", "maven": "maven",
              "gem": "gem", "cargo": "cargo", "composer": "composer"}


def _skip(path: Path) -> bool:
    return any(part in _SKIP_DIRS for part in path.parts)


def _find(repo: Path, name: str) -> List[Path]:
    """Every manifest of a given filename in the repo, excluding vendored trees."""
    out = []
    for p in repo.rglob(name):
        if p.is_file() and not _skip(p.relative_to(repo)):
            out.append(p)
    return out


def _purl(ecosystem: str, name: str, version: str, group: str = "") -> str:
    t = _PURL_TYPE.get(ecosystem, ecosystem)
    base = "pkg:{0}/".format(t)
    if group:
        base += "{0}/".format(group)
    base += name
    if version:
        base += "@" + version
    return base


class _Bag:
    """Collects unique components keyed by (ecosystem, name, version)."""
    def __init__(self):
        self.items: Dict[tuple, Dict[str, Any]] = {}

    def add(self, ecosystem: str, name: str, version: str = "",
            license: str = "", group: str = ""):
        name = (name or "").strip()
        version = (version or "").strip()
        if not name:
            return
        key = (ecosystem, group.lower(), name.lower(), version)
        if key in self.items:
            return
        comp: Dict[str, Any] = {
            "type": "library",
            "name": name,
            "purl": _purl(ecosystem, name, version, group),
            "properties": [{"name": "vhlocal:ecosystem", "value": ecosystem}],
        }
        if group:
            comp["group"] = group
        if version:
            comp["version"] = version
        if license:
            comp["licenses"] = [{"license": {"name": license}}]
        self.items[key] = comp


# --------------------------------------------------------------------------- #
# per-ecosystem parsers
# --------------------------------------------------------------------------- #

_REQ_LINE = re.compile(r"^\s*([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*"
                       r"(?:[=<>!~]=?\s*([0-9][^\s;#,]*))?")


def _p_requirements(repo, bag):
    for f in _find(repo, "requirements*.txt") + _find(repo, "requirements.txt"):
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "-", "git+", "http")):
                continue
            m = _REQ_LINE.match(line)
            if m:
                bag.add("pypi", m.group(1), m.group(2))


_TOML_DEP = re.compile(r'^\s*"?([A-Za-z0-9][A-Za-z0-9._-]*)"?\s*=\s*'
                       r'"?[\^~>=<]*([0-9][^",\s]*)')
_PEP_DEP = re.compile(r'"([A-Za-z0-9][A-Za-z0-9._-]*)\s*(?:\[[^\]]*\])?\s*'
                      r'(?:[=<>!~]=?\s*([0-9][^",;\s]*))?"')


def _p_pyproject(repo, bag):
    for f in _find(repo, "pyproject.toml"):
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        # PEP 621 [project] dependencies = ["flask>=2.0", ...]
        m = re.search(r'(?ms)^\s*dependencies\s*=\s*\[(.*?)\]', text)
        if m:
            for dm in _PEP_DEP.finditer(m.group(1)):
                bag.add("pypi", dm.group(1), dm.group(2) or "")
        # [tool.poetry.dependencies] flask = "^2.0"
        m = re.search(r'(?ms)\[tool\.poetry\.dependencies\](.*?)(?=^\[|\Z)', text)
        if m:
            for line in m.group(1).splitlines():
                dm = _TOML_DEP.match(line)
                if dm and dm.group(1).lower() != "python":
                    bag.add("pypi", dm.group(1), dm.group(2))


def _p_package_json(repo, bag):
    for f in _find(repo, "package.json"):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        for section in ("dependencies", "devDependencies", "peerDependencies"):
            for name, ver in (data.get(section) or {}).items():
                bag.add("npm", name, re.sub(r"^[\^~>=<\s]*", "", str(ver)))


def _p_go_mod(repo, bag):
    for f in _find(repo, "go.mod"):
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for m in re.finditer(r'(?m)^\s*(?:require\s+)?([\w./\-]+)\s+v([\w.\-+]+)', text):
            mod = m.group(1)
            if mod in ("require", "module", "go", "toolchain"):
                continue
            bag.add("golang", mod, "v" + m.group(2))


def _p_pom(repo, bag):
    ns = "{http://maven.apache.org/POM/4.0.0}"
    for f in _find(repo, "pom.xml"):
        try:
            root = ET.parse(str(f)).getroot()
        except (OSError, ET.ParseError):
            continue
        for dep in root.iter(ns + "dependency"):
            gid = dep.findtext(ns + "groupId", "").strip()
            aid = dep.findtext(ns + "artifactId", "").strip()
            ver = dep.findtext(ns + "version", "").strip()
            if aid and not ver.startswith("${"):
                bag.add("maven", aid, ver, group=gid)


def _p_gemfile_lock(repo, bag):
    for f in _find(repo, "Gemfile.lock"):
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        in_specs = False
        for line in text.splitlines():
            if line.strip() == "specs:":
                in_specs = True
                continue
            if in_specs:
                m = re.match(r"^\s{4}([A-Za-z0-9._-]+)\s+\(([^)]+)\)", line)
                if m:
                    bag.add("gem", m.group(1), m.group(2))
                elif line and not line.startswith(" "):
                    in_specs = False


def _p_cargo(repo, bag):
    for f in _find(repo, "Cargo.toml"):
        try:
            text = f.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        m = re.search(r'(?ms)^\[dependencies\](.*?)(?=^\[|\Z)', text)
        if not m:
            continue
        for line in m.group(1).splitlines():
            dm = _TOML_DEP.match(line)
            if dm:
                bag.add("cargo", dm.group(1), dm.group(2))
            else:
                # crate = { version = "1.0", ... }
                vm = re.match(r'\s*([A-Za-z0-9._-]+)\s*=\s*\{[^}]*version\s*=\s*"([^"]+)"', line)
                if vm:
                    bag.add("cargo", vm.group(1), vm.group(2))


def _p_composer(repo, bag):
    for f in _find(repo, "composer.json"):
        try:
            data = json.loads(f.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        for section in ("require", "require-dev"):
            for name, ver in (data.get(section) or {}).items():
                if name.lower() in ("php",) or name.startswith("ext-"):
                    continue
                bag.add("composer", name, re.sub(r"^[\^~>=<\s]*", "", str(ver)))


_PARSERS: List[Callable] = [
    _p_requirements, _p_pyproject, _p_package_json, _p_go_mod, _p_pom,
    _p_gemfile_lock, _p_cargo, _p_composer,
]


# --------------------------------------------------------------------------- #
# assembly
# --------------------------------------------------------------------------- #

def build_sbom(repo, timestamp: Optional[str] = None) -> Dict[str, Any]:
    """A CycloneDX 1.5 SBOM for the repo. Deterministic (components sorted)."""
    repo = Path(repo)
    bag = _Bag()
    for parse in _PARSERS:
        try:
            parse(repo, bag)
        except Exception:  # pragma: no cover - one bad manifest never fails the SBOM
            continue
    components = sorted(bag.items.values(),
                        key=lambda c: (c["properties"][0]["value"], c["name"].lower(),
                                       c.get("version", "")))
    metadata: Dict[str, Any] = {
        "tools": [{"vendor": "vhlocal", "name": "sbom"}],
        "component": {"type": "application", "name": repo.name or "application"},
    }
    if timestamp:
        metadata["timestamp"] = timestamp
    return {
        "bomFormat": "CycloneDX",
        "specVersion": CDX_VERSION,
        "version": 1,
        "metadata": metadata,
        "components": components,
    }


def summary(cdx: Dict[str, Any]) -> Dict[str, Any]:
    """{total, by_ecosystem, components:[{name,version,ecosystem,license}]} for the
    report / UI."""
    comps = cdx.get("components") or []
    by_eco: Dict[str, int] = {}
    rows = []
    for c in comps:
        eco = (c.get("properties") or [{}])[0].get("value", "?")
        by_eco[eco] = by_eco.get(eco, 0) + 1
        lic = ""
        if c.get("licenses"):
            lic = c["licenses"][0].get("license", {}).get("name", "")
        rows.append({"name": c["name"], "version": c.get("version", ""),
                     "ecosystem": eco, "license": lic,
                     "group": c.get("group", "")})
    return {"total": len(comps), "by_ecosystem": by_eco, "components": rows}


def write_sbom(results_dir, repo, timestamp: Optional[str] = None) -> Dict[str, Any]:
    """Write sbom.cdx.json into the results dir; return the summary. No components
    → still writes a valid empty SBOM (a repo may genuinely have no manifests)."""
    cdx = build_sbom(repo, timestamp)
    try:
        (Path(results_dir) / SBOM_FILE).write_text(
            json.dumps(cdx, indent=2), encoding="utf-8")
    except OSError:
        pass
    return summary(cdx)


def main(argv=None):   # `python -m vhlocal.sbom <repo> [--out sbom.cdx.json]`
    import argparse
    import sys
    ap = argparse.ArgumentParser(description="Generate a CycloneDX SBOM for a repo.")
    ap.add_argument("repo")
    ap.add_argument("--out", default=None, help="output path (default: ./sbom.cdx.json)")
    args = ap.parse_args(argv)
    cdx = build_sbom(args.repo)
    out = Path(args.out) if args.out else Path.cwd() / SBOM_FILE
    out.write_text(json.dumps(cdx, indent=2), encoding="utf-8")
    s = summary(cdx)
    print("SBOM: {0} components ({1}) -> {2}".format(
        s["total"], ", ".join("%s:%d" % (k, v) for k, v in sorted(s["by_ecosystem"].items())),
        out))
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
