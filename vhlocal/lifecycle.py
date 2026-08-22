"""Cross-run finding lifecycle (Mode A) — always on.

Turns a pile of independent scans of one target into a tracked history, without
touching the hunt itself. After a run's findings are finalized, we compare them
against the most recent *prior* report of the same repository and label each:

* **new** — no matching finding in the prior report.
* **persisting** — matched a finding that was present last time too.
* **regressed** — matches something the prior report recorded as *fixed*, i.e.
  it went away and has come back.

and separately list the findings that were present before and are **absent now**
(**fixed**). The keys of those fixed findings are written into ``findings.json``
so the *next* run can recognise a regression.

Reconciliation is deterministic and post-hoc: it reads prior artifacts off disk
and never calls a model, so it cannot change what the current run found. Run
independence — and therefore benchmark validity — is preserved. (Actively
*seeding* a new hunt with prior findings is a separate, opt-in behaviour handled
elsewhere as Mode B.)

Matching is by ``root_cause_key`` — the same line-number-free fingerprint used
to cluster duplicates within a run — so a finding that merely drifted a few
lines, or got relabelled to a sibling CWE in the same family, still matches its
prior self. A weak or absent key falls back to ``(normalized_cwe, file)``.
"""

import json
import re
import subprocess
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

from .knowledge import normalized_cwe as _normalized_cwe

FINDINGS_JSON = "findings.json"
SCAN_META = "scan_meta.json"

# Lifecycle states — the value written to Finding.finding_lifecycle.
NEW = "new"
PERSISTING = "persisting"
REGRESSED = "regressed"

_FILE_RE = re.compile(r"([\w./+\-]+\.[A-Za-z0-9]{1,6})")


def _fval(obj: Any, name: str) -> str:
    """Read a field from either a Finding object or a findings.json dict."""
    v = obj.get(name) if isinstance(obj, dict) else getattr(obj, name, None)
    return v if isinstance(v, str) else ("" if v is None else str(v))


def _loc_file(text: str) -> str:
    """First file-looking token in a location/data-flow string (basename kept)."""
    m = _FILE_RE.search(text or "")
    if not m:
        return ""
    return m.group(1).split("/")[-1]


def _normalize_family(rck: str) -> str:
    """Roll the leading family segment of a root-cause key up to its canonical
    CWE, so the same defect relabelled to a sibling CWE (e.g. CWE-863 → CWE-284,
    or CWE-943 vs CWE-89 within their families) still fingerprints identically
    across runs. The file / sink-function / flow-signature tail is preserved, so
    two distinct inputs reaching one sink stay separate."""
    head, sep, rest = rck.partition(":")
    if head.upper().startswith("CWE-"):
        nc = _normalized_cwe(head)
        if nc:
            head = nc
    return head + sep + rest


def _key(obj: Any) -> str:
    """Stable cross-run identity. Prefer the (family-normalized) root-cause
    fingerprint; fall back to normalized-CWE + file so a run that failed to
    compute a key still matches."""
    rck = _fval(obj, "root_cause_key")
    if rck:
        return _normalize_family(rck)
    cwe = _fval(obj, "normalized_cwe") or _fval(obj, "cwe")
    fil = _loc_file(_fval(obj, "location")) or _loc_file(_fval(obj, "data_flow"))
    if cwe and fil:
        return "cwefile:{0}:{1}".format(_normalized_cwe(cwe) or cwe.upper(), fil)
    return ""


def _is_dupe(obj: Any) -> bool:
    return bool(_fval(obj, "duplicate_of"))


# --------------------------------------------------------------------------- #
# git provenance (best-effort; the harness may run where git is absent)
# --------------------------------------------------------------------------- #
def git_provenance(repo: Path) -> Dict[str, Any]:
    """Commit / branch / dirty flag for the scanned tree, best-effort.

    Returns empty strings when the target is not a git repo or git is missing —
    the engine records whatever it can, and reconciliation degrades gracefully
    to 'no commit info' rather than failing."""
    out = {"git_commit": "", "git_branch": "", "git_dirty": False}
    repo = Path(repo)

    def _git(*args: str) -> str:
        try:
            p = subprocess.run(
                ["git", "-C", str(repo), *args],
                stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10)
            return p.stdout.decode("utf-8", "replace").strip() if p.returncode == 0 else ""
        except (OSError, subprocess.TimeoutExpired):
            return ""

    out["git_commit"] = _git("rev-parse", "HEAD")
    if out["git_commit"]:
        out["git_branch"] = _git("rev-parse", "--abbrev-ref", "HEAD")
        out["git_dirty"] = bool(_git("status", "--porcelain"))
    return out


# --------------------------------------------------------------------------- #
# prior-report discovery
# --------------------------------------------------------------------------- #
def _read_json(path: Path) -> Optional[Dict[str, Any]]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None


def find_prior_report(
    results_dir: Path,
    repo: str,
    started_at: float,
    reports_dir: Optional[Path] = None,
    extra_dirs: Optional[List[Path]] = None,
) -> Optional[Tuple[Path, Dict[str, Any]]]:
    """The most recent *other* report of the same ``repo`` that started before
    this run and has a parsed ``findings.json``. Returns (dir, findings_json) or
    None. Same-repo match is by the resolved path the engine recorded."""
    results_dir = Path(results_dir).resolve()
    want_repo = _norm_repo(repo)
    roots: List[Path] = []
    if reports_dir:
        roots.append(Path(reports_dir))
    roots.append(results_dir.parent)          # reports live as subdirs by default
    for d in extra_dirs or []:
        roots.append(Path(d))

    best: Optional[Tuple[float, Path, Dict[str, Any]]] = None
    seen: set = set()
    for root in roots:
        try:
            candidates = [p for p in Path(root).iterdir() if p.is_dir()]
        except OSError:
            continue
        for cand in candidates:
            rp = cand.resolve()
            if rp == results_dir or rp in seen:
                continue
            seen.add(rp)
            meta = _read_json(cand / SCAN_META)
            if not meta or _norm_repo(meta.get("repo", "")) != want_repo:
                continue
            when = float(meta.get("started_at") or 0)
            # Strictly-earlier runs only; ties (same stamp) are not "prior".
            if when >= started_at > 0:
                continue
            data = _read_json(cand / FINDINGS_JSON)
            if not data or not isinstance(data.get("findings"), list):
                continue
            if best is None or when > best[0]:
                best = (when, cand, data)
    if best is None:
        return None
    return best[1], best[2]


def _norm_repo(repo: str) -> str:
    if not repo:
        return ""
    try:
        return str(Path(repo).expanduser().resolve())
    except (OSError, RuntimeError):
        return str(repo).rstrip("/")


# --------------------------------------------------------------------------- #
# reconciliation
# --------------------------------------------------------------------------- #
def reconcile(
    findings: List[Any],
    results_dir: Path,
    meta: Dict[str, Any],
    reports_dir: Optional[Path] = None,
    extra_dirs: Optional[List[Path]] = None,
) -> Dict[str, Any]:
    """Label ``findings`` in place with their lifecycle state and return a
    summary. Deterministic: reads the prior report from disk, calls no model.

    The returned summary carries everything the renderers and the next run need:
    the prior report's identity + commit, the per-state counts, the list of
    findings that are now *fixed*, and ``fixed_keys`` (persisted into
    findings.json for regression detection on the following run)."""
    unique = [f for f in findings if not _is_dupe(f)]

    repo = meta.get("repo", "") or ""
    started_at = float(meta.get("started_at") or 0)
    prior = find_prior_report(results_dir, repo, started_at, reports_dir, extra_dirs)

    if prior is None:
        for f in findings:
            _set(f, "finding_lifecycle", "")
        return {
            "has_prior": False,
            "current_commit": meta.get("git_commit", "") or "",
            "new": 0, "persisting": 0, "regressed": 0, "fixed": 0,
            "fixed_findings": [],
            "fixed_keys": [_key(f) for f in unique if _key(f)],
        }

    prior_dir, prior_data = prior
    prior_meta = prior_data.get("meta") or {}
    prior_findings = [pf for pf in prior_data["findings"] if not _is_dupe(pf)]
    prior_lc = prior_data.get("lifecycle") or {}

    prior_keys = {_key(pf) for pf in prior_findings if _key(pf)}
    prior_fixed = set(prior_lc.get("fixed_keys") or [])

    cur_keys: set = set()
    counts = {NEW: 0, PERSISTING: 0, REGRESSED: 0}
    for f in unique:
        k = _key(f)
        if k:
            cur_keys.add(k)
        if k and k in prior_keys:
            state = PERSISTING
        elif k and k in prior_fixed:
            state = REGRESSED
        else:
            state = NEW
        _set(f, "finding_lifecycle", state)
        counts[state] += 1
    # Clustered duplicates inherit their canonical member's state for display.
    canon_state = {_key(f): _fval(f, "finding_lifecycle") for f in unique if _key(f)}
    for f in findings:
        if _is_dupe(f):
            _set(f, "finding_lifecycle", canon_state.get(_key(f), ""))

    # Present before, absent now → fixed. Record their keys for the next run.
    fixed_findings = []
    for pf in prior_findings:
        k = _key(pf)
        if k and k not in cur_keys:
            fixed_findings.append({
                "id": _fval(pf, "id"),
                "title": _fval(pf, "title"),
                "cwe": _fval(pf, "normalized_cwe") or _fval(pf, "cwe"),
                "location": _fval(pf, "location"),
                "key": k,
            })

    return {
        "has_prior": True,
        "prior_report": prior_dir.name,
        "prior_commit": prior_meta.get("git_commit", "") or "",
        "prior_started_at": float(prior_meta.get("started_at") or 0),
        "current_commit": meta.get("git_commit", "") or "",
        "new": counts[NEW],
        "persisting": counts[PERSISTING],
        "regressed": counts[REGRESSED],
        "fixed": len(fixed_findings),
        "fixed_findings": fixed_findings,
        # Keys still fixed as of this run: prior fixed set minus any that came
        # back (now present), plus the newly-fixed ones.
        "fixed_keys": sorted(
            (prior_fixed - cur_keys) | {ff["key"] for ff in fixed_findings}),
    }


def _set(obj: Any, name: str, value: str) -> None:
    if isinstance(obj, dict):
        obj[name] = value
    else:
        setattr(obj, name, value)


# --------------------------------------------------------------------------- #
# Mode B — prior-report seeding of the hunt (opt-in, off by default)
# --------------------------------------------------------------------------- #
# Seeding hands Phase 1 the *locations* a prior scan already flagged, as leads to
# independently re-verify. It correlates this run with the prior one — good for
# production regression-tracking, bad for benchmarking (it breaks the run
# independence that union-recall measurement assumes). That is exactly why it is
# opt-in and why the engine records that a run was seeded, so a seeded run is
# never mistaken for an independent sample.
_MAX_HOTSPOTS = 40


def prior_hotspots_markdown(
    results_dir: Path,
    repo: str,
    started_at: float,
    reports_dir: Optional[Path] = None,
    extra_dirs: Optional[List[Path]] = None,
) -> Tuple[str, str]:
    """Build the 'known hot spots' seed block from the most recent prior report,
    or ("", "") if there is none. Returns (markdown, prior_report_name).

    The block lists each prior finding's location + canonical family, framed
    unambiguously as leads to *re-verify*, never as confirmed facts — a seeded
    hunt must still independently prove the data-flow, because the code may have
    changed since the prior scan."""
    prior = find_prior_report(results_dir, repo, started_at, reports_dir, extra_dirs)
    if prior is None:
        return "", ""
    prior_dir, data = prior
    findings = [f for f in data.get("findings", []) if not _is_dupe(f)]

    rows = []
    for f in findings:
        loc = _fval(f, "location")
        if not loc:
            continue
        fam = _fval(f, "canonical_name") or _fval(f, "normalized_cwe") or _fval(f, "cwe")
        title = _fval(f, "title")
        rows.append((loc, fam, title))
        if len(rows) >= _MAX_HOTSPOTS:
            break
    if not rows:
        return "", prior_dir.name

    lines = [
        "## Known hot spots from a prior scan of this target",
        "",
        "A previous scan (`{0}`) reported the findings below. Treat each as a "
        "**lead to independently re-verify — NOT a confirmed vulnerability**. The "
        "code may have changed since; a location listed here may already be "
        "fixed. Confirm the vulnerable source→sink data-flow still exists in "
        "the current code before relying on it, and do not let this list narrow "
        "your search — hunt the whole attack surface as usual.".format(
            prior_dir.name),
        "",
        "| Prior location | Family | Prior title |",
        "|---|---|---|",
    ]
    for loc, fam, title in rows:
        lines.append("| `{0}` | {1} | {2} |".format(
            loc, fam or "—", (title or "—")[:70]))
    if len(findings) > len(rows):
        lines.append("")
        lines.append("_(Showing {0} of {1}; some prior findings had no location.)_"
                     .format(len(rows), len(findings)))
    return "\n".join(lines) + "\n", prior_dir.name
