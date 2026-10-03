"""Export an offline oracle from the independent Python reference.

Run explicitly during migration; normal Go tests only consume the JSON output.
No target modules, models, network, or generated reproduction tests are executed.
"""
import copy
import hashlib
import json
import sys
import tempfile
from pathlib import Path

reference = Path(sys.argv[1]).resolve()
output = Path(sys.argv[2])
sys.path.insert(0, str(reference))
from vhlocal.consolidate import Finding
from vhlocal.verification import reconcile, source_identity, validate_artifacts

source = "def query(q):\n    return conn.execute(q)\n"
finding = dict(id="CAND-contract", title="SQL injection in query", cwe="CWE-89",
               location="app.py:2", entry_point="GET /search", data_flow="q -> conn.execute(q)")
decision = dict(candidate_id="CAND-contract", verdict="supported",
                rationale="request-controlled q reaches SQL execution", reviewer="reference-fixture",
                entry_point="GET /search", attacker_control="q query parameter", preconditions="none",
                defenses_reviewed="none observed", security_impact="database disclosure", revision="rev1",
                unresolved_questions=[], evidence=[dict(path="app.py", start_line=1, end_line=2,
                                                       quote=source.rstrip())])
rows = [("missing_decision", []),
        ("duplicate_decisions", [copy.deepcopy(decision), copy.deepcopy(decision)])]
for verdict in ("supported", "rejected"):
    valid = dict(copy.deepcopy(decision), verdict=verdict)
    rows.append(("complete_" + verdict, [valid]))
    for field in ("reviewer", "entry_point", "attacker_control", "preconditions", "defenses_reviewed", "security_impact"):
        invalid = copy.deepcopy(valid)
        invalid[field] = ""
        rows.append((verdict + "_missing_" + field, [invalid]))
    rows.append((verdict + "_stale_revision", [dict(copy.deepcopy(valid), revision="old")]))
rows.append(("explicit_unresolved", [dict(copy.deepcopy(decision), verdict="unresolved")]))
rows.append(("contradictory_support", [dict(copy.deepcopy(decision), unresolved_questions=["is q controlled?"])]))
rows.append(("wrong_quote", [dict(copy.deepcopy(decision), evidence=[dict(path="app.py", start_line=1, end_line=2, quote="invented")])]))

with tempfile.TemporaryDirectory() as temporary:
    root = Path(temporary)
    (root / "app.py").write_text(source)
    manifest = dict(schema_version=1, repo=str(root), revision="rev1",
                    candidates=[dict(id="CAND-contract", finding=finding)])
    cases = []
    for name, decisions in rows:
        result = reconcile(manifest, decisions, root)
        cases.append(dict(name=name, decisions=decisions,
                          expected=dict(complete=result["complete"], status=result["results"][0]["status"])))

    identity_source = "class First:\n    def query(self, q):\n        conn.execute(q)\n        conn.execute(q)\n\nclass Second:\n    def query(self, q):\n        conn.execute(q)\n"
    (root / "sites.py").write_text(identity_source)
    locations = ["sites.py:3", "sites.py:4", "sites.py:8", "sites.py:3"]
    identities = [source_identity(Finding(**dict(finding, location=loc)), root) for loc in locations]
    artifact_cases = []
    supported = Finding(**finding, verification_status="supported")
    for name, entries in [("empty", []), ("deferred", [dict(candidate_id="CAND-contract", kind="deferred", reason="needs isolated database")]),
                          ("unexplained_deferral", [dict(candidate_id="CAND-contract", kind="deferred")]),
                          ("missing_file", [dict(candidate_id="CAND-contract", kind="test", path="exploit_tests/test.py", status="authored")])]:
        (root / "artifact_manifest.json").write_text(json.dumps(entries))
        artifact_cases.append(dict(name=name, entries=entries, valid=not validate_artifacts(root, [supported])))

result = dict(reference_files_sha256={name: hashlib.sha256((reference / "vhlocal" / name).read_bytes()).hexdigest()
                                      for name in ("verification.py", "evidence.py", "quality.py")},
              source=source, finding=finding, cases=cases,
              identity=dict(source=identity_source, locations=locations, unique_count=len(set(identities))),
              artifact_cases=artifact_cases)
output.write_text(json.dumps(result, indent=2) + "\n")
