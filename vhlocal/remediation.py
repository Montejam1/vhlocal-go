"""Remediation & fix-verification — the Visa-harness `remediate` + `validate`
capabilities, adapted to vhlocal's static-only, local-first design.

Three layers, all deterministic and stdlib-only:

* **Report-only DTOs** — per confirmed finding, a structured remediation record
  (finding + proposed fix + status) written under ``remediation/<VULN-NNN>/``.
  Built from the fix strategy the report already produces; **no source is edited**,
  which keeps a plain scan static-only. A model-generated unified diff can be
  dropped into the DTO later without changing this structure.
* **Patch safety** — parse a unified diff's target paths and prove they are
  confined to the repo (no traversal, no absolute escape) before anything is
  applied. This is the important, deterministic half of any fix-apply.
* **Isolated apply** — apply a diff in a throwaway copy of the repo, never the
  user's working tree. Opt-in; the safety check gates it.
* **Validation scoring** — turn a panel's per-gate votes into a
  Fixed / Partially Fixed / Not Fixed / Unverifiable verdict via configurable
  weights (the host side of an agentic validation panel).
"""

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

REMEDIATION_DIR = "remediation"

# ---------------------------------------------------------------------------
# Report-only remediation DTOs
# ---------------------------------------------------------------------------


def _val(f: Any, name: str) -> str:
    v = f.get(name) if isinstance(f, dict) else getattr(f, name, None)
    return v if isinstance(v, str) else ("" if v is None else str(v))


def _slug(fid: str) -> str:
    return re.sub(r"[^A-Za-z0-9._-]", "_", fid or "finding")


def build_dtos(findings: List[Any]) -> List[Dict[str, Any]]:
    """One remediation DTO per confirmed (non-duplicate) finding that carries a
    fix. Deterministic; status is ``proposed`` (a fix is described, none applied)."""
    dtos = []
    for f in findings:
        if _val(f, "duplicate_of"):
            continue
        fid = _val(f, "id")
        fix = _val(f, "fix")
        if not fid:
            continue
        dtos.append({
            "id": fid,
            "title": _val(f, "title"),
            "cwe": _val(f, "normalized_cwe") or _val(f, "cwe"),
            "severity": _val(f, "severity"),
            "location": _val(f, "location"),
            "fix_strategy": fix or "(no fix strategy recorded)",
            "has_fix": bool(fix),
            "diff": None,            # filled by an optional model-backed patch step
            "status": "proposed",    # proposed -> patched -> validated/…
            "validation": None,      # filled by score_validation() output
        })
    return dtos


def write_remediation(results_dir, findings: List[Any]) -> Dict[str, Any]:
    """Write the per-finding DTOs under ``remediation/<VULN-NNN>/remediate.json``
    plus a human ``summary.md``. Returns a coverage summary. Report-only: never
    touches the scanned repo."""
    dtos = build_dtos(findings)
    root = Path(results_dir) / REMEDIATION_DIR
    with_fix = 0
    for dto in dtos:
        d = root / _slug(dto["id"])
        d.mkdir(parents=True, exist_ok=True)
        (d / "remediate.json").write_text(json.dumps(dto, indent=2), encoding="utf-8")
        (d / "summary.md").write_text(
            "# {0} — {1}\n\n**CWE:** {2}  \n**Severity:** {3}  \n"
            "**Location:** `{4}`\n\n## Proposed fix\n\n{5}\n\n"
            "_Status: {6} (report-only — no source was modified)._\n".format(
                dto["id"], dto["title"], dto["cwe"], dto["severity"],
                dto["location"], dto["fix_strategy"], dto["status"]),
            encoding="utf-8")
        if dto["has_fix"]:
            with_fix += 1
    summary = {"total": len(dtos), "with_fix": with_fix,
               "dir": str(root) if dtos else ""}
    if dtos:
        (root / "index.json").write_text(
            json.dumps({"summary": summary,
                        "findings": [{"id": d["id"], "status": d["status"],
                                      "has_fix": d["has_fix"]} for d in dtos]},
                       indent=2), encoding="utf-8")
    return summary


# ---------------------------------------------------------------------------
# Patch safety + isolated apply (opt-in fix mode)
# ---------------------------------------------------------------------------

_DIFF_TARGET = re.compile(r"^\+\+\+ (?:b/)?(.+)$", re.MULTILINE)
_DIFF_SOURCE = re.compile(r"^--- (?:a/)?(.+)$", re.MULTILINE)


def diff_target_paths(diff_text: str) -> List[str]:
    """Repo-relative paths a unified diff writes to (the +++ side), /dev/null
    (file creation/deletion markers) excluded."""
    out = []
    for m in _DIFF_TARGET.finditer(diff_text or ""):
        p = m.group(1).strip()
        # strip a trailing tab-timestamp some diffs carry
        p = p.split("\t")[0].strip()
        if p and p != "/dev/null":
            out.append(p)
    return out


def patch_confined(diff_text: str, repo) -> Tuple[bool, List[str]]:
    """(ok, escaping_paths). A diff is safe to apply only if every target path
    resolves *inside* the repo — no ``..`` traversal, no absolute path escape."""
    repo_r = Path(repo).resolve()
    bad = []
    paths = diff_target_paths(diff_text)
    for p in paths:
        if os.path.isabs(p):
            bad.append(p)
            continue
        target = (repo_r / p).resolve()
        if target != repo_r and not str(target).startswith(str(repo_r) + os.sep):
            bad.append(p)
    return (not bad and bool(paths)), bad


def apply_in_worktree(repo, diff_text: str) -> Dict[str, Any]:
    """Apply a diff to a THROWAWAY copy of the repo (never the user's tree). The
    safety check gates it. Returns {applied, worktree, message}. Requires `git`."""
    ok, bad = patch_confined(diff_text, repo)
    if not ok:
        return {"applied": False, "worktree": "",
                "message": "refused: diff targets escape the repo: {0}".format(bad)
                if bad else "refused: diff has no in-repo target paths"}
    work = Path(tempfile.mkdtemp(prefix="vhlocal-fix-"))
    tree = work / "tree"
    try:
        shutil.copytree(repo, tree,
                        ignore=shutil.ignore_patterns(".git", "node_modules",
                                                      "__pycache__", ".venv"))
        (work / "fix.patch").write_text(diff_text, encoding="utf-8")
        r = subprocess.run(
            ["git", "apply", "--reject", "--whitespace=nowarn",
             str(work / "fix.patch")],
            cwd=str(tree), capture_output=True, text=True, timeout=60)
        if r.returncode == 0:
            return {"applied": True, "worktree": str(tree),
                    "message": "applied cleanly in isolated worktree"}
        return {"applied": False, "worktree": str(tree),
                "message": "git apply failed: {0}".format(
                    (r.stderr or r.stdout or "").strip()[:300])}
    except (OSError, subprocess.SubprocessError) as exc:
        return {"applied": False, "worktree": str(tree),
                "message": "apply error: {0}".format(exc)}


# ---------------------------------------------------------------------------
# Validation scoring — the host side of an agentic validation panel
# ---------------------------------------------------------------------------

# Default gates and weights for grading a fix. A panel (or a reviewer) supplies a
# per-gate outcome; the host computes the verdict deterministically from these.
DEFAULT_WEIGHTS = {
    "root_cause_addressed": 0.45,   # does the fix remove the actual defect?
    "bypass_resistant": 0.35,       # can the pen-tester lens still bypass it?
    "no_regression": 0.20,          # does the fix avoid breaking behavior?
}
_OUTCOME = {"pass": 1.0, "partial": 0.5, "fail": 0.0}

FIXED = "fixed"
PARTIALLY_FIXED = "partially_fixed"
NOT_FIXED = "not_fixed"
UNVERIFIABLE = "unverifiable"


def score_validation(gates: Dict[str, str],
                     weights: Optional[Dict[str, float]] = None) -> Dict[str, Any]:
    """Turn per-gate outcomes into a verdict.

    gates: {gate_name: 'pass'|'partial'|'fail'|'unknown'}. A gate the panel could
    not decide ('unknown' / missing) contributes no score and shrinks the decided
    weight; if too little weight was decided, the verdict is UNVERIFIABLE rather
    than a falsely-confident pass/fail."""
    w = weights or DEFAULT_WEIGHTS
    total_w = sum(w.values()) or 1.0
    decided_w = 0.0
    earned = 0.0
    for gate, weight in w.items():
        outcome = (gates.get(gate) or "unknown").lower()
        if outcome in _OUTCOME:
            decided_w += weight
            earned += weight * _OUTCOME[outcome]
    if decided_w < 0.5 * total_w:
        return {"verdict": UNVERIFIABLE, "score": None,
                "decided_fraction": round(decided_w / total_w, 3), "gates": gates}
    score = earned / decided_w
    if score >= 0.85:
        verdict = FIXED
    elif score >= 0.40:
        verdict = PARTIALLY_FIXED
    else:
        verdict = NOT_FIXED
    return {"verdict": verdict, "score": round(score, 3),
            "decided_fraction": round(decided_w / total_w, 3), "gates": gates}
