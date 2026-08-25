"""SARIF 2.1.0 export — machine-ingestible findings for CI / code-scanning.

Deterministic transform of the engine-built findings (findings.json) into SARIF
2.1.0, so vhlocal output drops into GitHub code-scanning, DefectDojo, and any
SARIF viewer. Mirrors the fields the Markdown report already carries; the CWE
taxonomy comes from knowledge.py (the same canonical families the report uses).
Stdlib only.
"""

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from . import knowledge

SARIF_VERSION = "2.1.0"
SARIF_SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
DRIVER_NAME = "vhlocal"
CWE_TAXONOMY_GUID = "b7d3f2a0-6c1e-4f5b-9a2d-1e0c4f8b3a11"  # stable, arbitrary
FINDINGS_SARIF_FILE = "findings.sarif"

# Severity → SARIF level. vhlocal tiers: Critical / High+ / High / Medium / Low /
# Info(ormational) / Unrated.
_LEVEL = {
    "critical": "error", "high+": "error", "high": "error",
    "medium": "warning", "low": "note", "info": "note",
    "informational": "note", "unrated": "none", "unknown": "none",
}
_LOC_RE = re.compile(r"([\w./+\-]+\.[A-Za-z0-9]{1,6})(?:[:\s]+(\d+))?")


def _level(sev: str) -> str:
    return _LEVEL.get((sev or "").strip().lower(), "none")


def _cwe_num(cwe: str) -> str:
    m = re.search(r"(\d+)", cwe or "")
    return m.group(1) if m else ""


def _mitre_url(num: str) -> str:
    return "https://cwe.mitre.org/data/definitions/{0}.html".format(num)


def _parse_location(text: str):
    """(uri, startLine|None) from a location/data-flow string, or (None, None)."""
    m = _LOC_RE.search(text or "")
    if not m:
        return None, None
    uri = m.group(1)
    line = int(m.group(2)) if m.group(2) else None
    return uri, line


def _rule_id(f: Dict[str, Any]) -> str:
    return (f.get("normalized_cwe") or f.get("cwe") or f.get("cwe_family")
            or "VULN").strip()


def build_sarif(findings: List[Dict[str, Any]], meta: Dict[str, Any],
                run_status: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """Build a SARIF 2.1.0 log from finding dicts + scan meta. Duplicates are
    excluded (SARIF results are unique defects; dedup call sites become
    relatedLocations elsewhere)."""
    run_status = run_status or {}
    uniq = [f for f in findings if not f.get("duplicate_of")]

    rules: Dict[str, Dict[str, Any]] = {}
    taxa: Dict[str, Dict[str, Any]] = {}
    results: List[Dict[str, Any]] = []

    for f in uniq:
        rid = _rule_id(f)
        cwe = f.get("normalized_cwe") or f.get("cwe") or ""
        num = _cwe_num(cwe)
        name = (f.get("canonical_name") or knowledge.canonical_name(cwe)
                or f.get("title") or rid)
        if rid not in rules:
            rule: Dict[str, Any] = {
                "id": rid,
                "name": (name or rid).replace(" ", ""),
                "shortDescription": {"text": name or rid},
                "properties": {"category": rid},
            }
            if num:
                rule["helpUri"] = _mitre_url(num)
                rule["relationships"] = [{
                    "target": {"id": "CWE-" + num, "toolComponent":
                               {"name": "CWE", "guid": CWE_TAXONOMY_GUID}},
                    "kinds": ["superset"],
                }]
            rules[rid] = rule
        if num and ("CWE-" + num) not in taxa:
            taxa["CWE-" + num] = {
                "id": "CWE-" + num,
                "name": name or ("CWE-" + num),
                "helpUri": _mitre_url(num),
            }

        uri, line = _parse_location(f.get("location") or "")
        phys: Dict[str, Any] = {}
        if uri:
            phys["artifactLocation"] = {"uri": uri}
            if line:
                phys["region"] = {"startLine": line}
        sev = f.get("normalized_severity") or f.get("severity") or "Unrated"
        msg = f.get("title") or name or rid
        props: Dict[str, Any] = {"severity": sev}
        if cwe:
            props["cwe"] = cwe
            if num:
                props["cweId"] = "CWE-" + num
                props["cweName"] = name
        if f.get("finding_lifecycle"):
            props["lifecycle"] = f["finding_lifecycle"]
        if f.get("votes"):
            props["votes"] = "{0} of {1} runs".format(
                f.get("votes"), f.get("vote_samples") or f.get("votes"))
            props["voteCount"] = f.get("votes")
        if f.get("id"):
            props["findingId"] = f["id"]
        res: Dict[str, Any] = {
            "ruleId": rid,
            "level": _level(sev),
            "message": {"text": "[{0}] {1}".format(sev, msg)},
            "properties": props,
        }
        if phys:
            res["locations"] = [{"physicalLocation": phys}]
        if num:
            res["taxa"] = [{"id": "CWE-" + num, "toolComponent":
                            {"name": "CWE", "guid": CWE_TAXONOMY_GUID}}]
        results.append(res)

    # A run is "successful" when execution completed; degraded coverage is a
    # notification, not a hard failure (mirrors the Visa harness contract).
    reasons = list(run_status.get("coverage_degraded_reasons") or [])
    if meta.get("hunt_halted_reason") and meta["hunt_halted_reason"] not in reasons:
        reasons.insert(0, meta["hunt_halted_reason"])
    execution_ok = (run_status.get("execution_status") or "complete") == "complete"
    invocation: Dict[str, Any] = {"executionSuccessful": bool(execution_ok)}
    if reasons:
        invocation["toolExecutionNotifications"] = [
            {"level": "warning", "message": {"text": r}} for r in reasons]

    run_props: Dict[str, Any] = {}
    if meta.get("repo"):
        run_props["applicationId"] = Path(meta["repo"]).name
    if meta.get("model"):
        run_props["huntModel"] = meta["model"]

    driver: Dict[str, Any] = {
        "name": DRIVER_NAME,
        "informationUri": "https://github.com/vulnhunter/vhlocal",
        "rules": list(rules.values()),
        "supportedTaxonomies": [{"name": "CWE", "guid": CWE_TAXONOMY_GUID}],
    }
    if meta.get("engine_version"):
        driver["version"] = meta["engine_version"]

    run: Dict[str, Any] = {
        "tool": {"driver": driver},
        "results": results,
        "invocations": [invocation],
        "taxonomies": [{
            "name": "CWE",
            "guid": CWE_TAXONOMY_GUID,
            "organization": "MITRE",
            "shortDescription": {"text": "Common Weakness Enumeration"},
            "taxa": list(taxa.values()),
        }],
    }
    if run_props:
        run["properties"] = run_props

    return {"$schema": SARIF_SCHEMA, "version": SARIF_VERSION, "runs": [run]}


def write_sarif(results_dir, findings: List[Dict[str, Any]], meta: Dict[str, Any],
                run_status: Optional[Dict[str, Any]] = None) -> Path:
    """Write findings.sarif into the results dir; return its path."""
    doc = build_sarif(findings, meta, run_status)
    out = Path(results_dir) / FINDINGS_SARIF_FILE
    out.write_text(json.dumps(doc, indent=2), encoding="utf-8")
    return out
