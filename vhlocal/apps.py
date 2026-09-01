"""Named applications — the human handle that ties a target's scans, ledger,
SBOM, and threat model together.

An application is keyed by the SAME slug the vulnerability ledger uses
(``membank._slug`` of the resolved repo path), so "application", "ledger", and the
scans of a folder are one identity. The registry here stores only the friendly
name + provenance; the scans, ledger, SBOM and threat model are all discovered by
that slug elsewhere. The first scan of a path names it; later scans of the same
path auto-associate.

Stored as one JSON file next to the ledger dir (so a test's VHLOCAL_LEDGER_DIR
override isolates both). Stdlib only.
"""

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from .membank import _slug as target_slug, ledger_dir


def apps_file() -> Path:
    return ledger_dir().parent / "applications.json"


def slug_for(repo: Any) -> str:
    """The application slug for a repo path — identical to the ledger's slug."""
    return target_slug(str(repo or ""))


def _load() -> Dict[str, Any]:
    try:
        return json.loads(apps_file().read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return {}


def _save(data: Dict[str, Any]) -> None:
    p = apps_file()
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps(data, indent=2), encoding="utf-8")
    except OSError:
        pass


def get_by_slug(slug: str) -> Optional[Dict[str, Any]]:
    return _load().get(slug)


def get_application(repo: Any) -> Optional[Dict[str, Any]]:
    return get_by_slug(slug_for(repo))


def _default_name(repo: Any, slug: str) -> str:
    return Path(str(repo or "")).name or slug


def register(repo: Any, name: Optional[str] = None, when: float = 0.0) -> Dict[str, Any]:
    """Create the application on first sight (naming it), or touch an existing one.

    A non-empty ``name`` sets/updates the label; otherwise the folder name is used
    as the default on creation. Idempotent — subsequent scans of the same path
    keep the existing name unless a new one is given. Un-hides a previously
    forgotten app (a new scan brings it back). Returns the entry."""
    data = _load()
    slug = slug_for(repo)
    entry = data.get(slug)
    if entry is None or entry.get("hidden"):
        nm = (name or "").strip() or _default_name(repo, slug)
        entry = {"slug": slug, "name": nm, "repo": str(repo or ""),
                 "created": when, "updated": when}
        data[slug] = entry
    else:
        if name and name.strip():
            entry["name"] = name.strip()
        if repo:
            entry["repo"] = str(repo)
        if when:
            entry["updated"] = when
    _save(data)
    return entry


def hide(slug: str) -> bool:
    """Forget an application: drop its name/registration and mark it hidden so it
    no longer appears in the Apps list, even though its scan reports remain on
    disk. Re-scanning the folder un-hides it (see register). Returns True if the
    slug was known."""
    data = _load()
    existed = slug in data
    data[slug] = {"slug": slug, "hidden": True}
    _save(data)
    return existed


def hidden_slugs() -> set:
    """Slugs the user has forgotten — excluded from the Apps list even when their
    reports/ledger still exist."""
    return {s for s, e in _load().items() if isinstance(e, dict) and e.get("hidden")}


def set_name(slug: str, name: str, repo: Any = "", when: float = 0.0
             ) -> Optional[Dict[str, Any]]:
    """Name (or rename) an application BY SLUG — creating the registry entry if it
    doesn't exist yet, so an auto-discovered app (found via its reports/ledger but
    never named) can be named on first edit. Returns the entry, or None on a blank
    name. ``repo`` is stored for provenance but the slug is the identity."""
    if not (name or "").strip():
        return None
    data = _load()
    entry = data.get(slug)
    if entry is None:
        entry = {"slug": slug, "name": name.strip(), "repo": str(repo or ""),
                 "created": when, "updated": when}
        data[slug] = entry
    else:
        entry["name"] = name.strip()
        if repo:
            entry["repo"] = str(repo)
        if when:
            entry["updated"] = when
    _save(data)
    return entry


def list_applications() -> List[Dict[str, Any]]:
    """All registered (non-hidden) applications, most-recently-updated first."""
    vis = [e for e in _load().values() if isinstance(e, dict) and not e.get("hidden")]
    return sorted(vis, key=lambda a: -(a.get("updated") or 0))


_VALID_SLUG = re.compile(r"^[A-Za-z0-9._-]+$")


def is_valid_slug(slug: str) -> bool:
    """Guard for slugs arriving from the browser — no path separators / traversal."""
    return bool(slug) and bool(_VALID_SLUG.match(slug)) and ".." not in slug
