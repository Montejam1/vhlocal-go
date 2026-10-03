# Contract: On-disk Artifacts (byte-compatible)

The Go port MUST write these files with the same names, locations, and field semantics as the Python implementation. JSON is emitted with 2-space indent; field order follows the struct/dataclass declaration order shown (JSON consumers are order-insensitive, but preserving order keeps diffs clean). The `verification_*` writers append a trailing newline and write atomically (temp file + rename). Source of truth: `engine.py`, `consolidate.py`, `sarif.py`, `sbom.py`, `manifest.py`, `verification.py`, `inventory.py`, `membank.py`, `apps.py`, `knowledge.py`, `lifecycle.py`, `phases.py`.

## Results directory & files

- **Name** (when `--out` absent): `<repo-name>_VULNHUNT_RESULTS_<model-tag>_<YYYY-MM-DD-HHMMSS>` (local time), under `--reports-dir`/default. The `run_id` everywhere = this dir's basename. External tooling globs `*_VULNHUNT_RESULTS_*` — preserve exactly.
- **Files written**: `scan_meta.json`, `findings.json`, `findings.sarif`, `run_manifest.json`, `coverage_ledger.json`, `authz_map.json`, `sbom.cdx.json` (when threat-model/SBOM ran), `SCAN_REPORT.md`, `SCAN_REPORT.html`, `prompts.jsonl`, `errors.jsonl`, the verification set (below), `README.md` (Phase 4), per-phase `.md` outputs, `results/` (hunt), `sink_driven.md`/`iac` audit files, `remediation/` (when `--remediate`), `.vhlocal_state.json` (resume).
- **Phase output map**: 1→`phase1_output.md`, 1t→`threat_model.md`, 2→`results/` (dir of `sg-*.md`/`*.md`), 2b→`phase2b_output.md` (+`phase2b_handoff.md`), 3→`phase3_output.md`, 3d→`phase3d_output.md`, 4→`README.md`.
- **Deliverable-for-completion map** (resume validity): 1→phase1_output.md, 2→results/ (non-empty), 2b→phase2b_output.md, 3→phase3_output.md, 3d→phase3d_output.md, 4→README.md.
- **`.vhlocal_state.json`**: `{"completed":[phase_key,...]}`; defaults `{"completed":[]}` when missing/unparsable.
- **`prompts.jsonl`**: line 1 `{"kind":"system","prompt":...}`; then `{"kind":"agent","phase":...,"label":...,"chars":int,"prompt":...}` per agent.

## scan_meta.json (RunRecord)
Full field list (order + defaults) as in data-model.md §RunRecord. `agents[]` element: `{label,phase,model,turns,stopped_reason}` (`stopped_reason="complete"` when done; deterministic phases record `model:"deterministic",turns:0`).

## findings.json
Top-level keys in order: `meta` (the full scan_meta dict), `attribution` `{hunt_model, falsification_model, orchestrator:"vhlocal <ver>"}`, `run_status` `{execution_status, coverage_status, coverage_degraded_reasons:[str], validation_mode}`, `coverage` `{total_entry_points,reviewed,not_reviewed,complete}|null`, `counts` (severity-label→int over non-dups), `assessment` `{candidates,supported,unresolved,statically_supported,reviewed,hypotheses,reproduced}`, `verification` (reconciliation object|null), `vulnerability_counts` (over substantiated), `hypothesis_counts` (over hypotheses), `lifecycle` (see below), `vulnerability_ledger` (membank coverage summary|null), `chains` (list), `remediation` (object|null, only when remediate), `application_intelligence` `{sbom: <summary>|null}`, `findings` (list incl. duplicates; consumers filter on `duplicate_of`).

Per-finding: the full `Finding` field set in data-model.md §Finding, plus `potential_severity` (mirror of `severity`) appended by `to_dict()`. Severity normalization: when `normalized_severity` differs from `severity`, `reported_severity` = old value and `severity`/`severity_rank` become the normalized tier.

## findings.sarif (SARIF 2.1.0)
`{$schema:<sarif 2.1.0 url>, version:"2.1.0", runs:[run]}`. Driver name `vhlocal`, `informationUri:"https://github.com/vulnhunter/vhlocal"`, CWE taxonomy GUID `b7d3f2a0-6c1e-4f5b-9a2d-1e0c4f8b3a11`. Duplicates excluded.
- `rule` keyed by `rid` = normalized_cwe|cwe|cwe_family|"VULN": `{id, name(name w/o spaces), shortDescription.text, properties.category}` + when CWE numeric: `helpUri` mitre URL + `relationships:[{target:{id:"CWE-<n>",toolComponent:{name:"CWE",guid}},kinds:["superset"]}]`.
- `result`: `ruleId=rid`; `level` from `_LEVEL` map (critical/high+/high→error, medium→warning, low/info/informational→note, unrated/unknown→none) but forced `"note"` when not substantiated; `kind` = `"fail"` if substantiated (classification∈{statically_supported,reviewed}) else `"review"`; `message.text="[{classification}; potential severity: {sev}] {msg}"`; `properties:{severity,classification,hypothesisReason,assessmentReason(default "No substantiated review is recorded."),cwe?,cweId?,cweName?,lifecycle?,votes?,voteCount?,findingId?}`; `locations` from `_LOC_RE` (`([\w./+\-]+\.[A-Za-z0-9]{1,6})(?:[:\s]+(\d+))?`); `taxa` when CWE numeric.
- `invocations:[{executionSuccessful:(run_status.execution_status||"complete")=="complete", toolExecutionNotifications:[{level:"warning",message:{text:reason}}]...}]` (one per degraded/hunt-halt reason).
- `taxonomies:[{name:"CWE",guid,organization:"MITRE",shortDescription,taxa}]`; optional run `properties:{applicationId,huntModel}`.

## coverage_ledger.json
`{total,reviewed,not_reviewed,complete,counts:{disposition→int},entries:[{method,path,file,line,subsystem,disposition,evidence}]}`. `complete = total>0 && not_reviewed==0`. Disposition enum: `finding_emitted`, `reviewed_no_issue`, `covered_by_parent_analysis`, `excluded_with_reason`, `not_reviewed`. `null`/absent when repo dir missing.

## run_manifest.json
`{tool:{name:"vhlocal",version}, run_id, target:{repo,git_commit,git_branch}, models:{hunt,verify,recon,reproduce}, transport:{backend,host}, config:{hash:"sha256:<16hex>",num_ctx,max_partitions,phase2_mode,quality_strictness,phases_requested:[],seed_prior,ledger,redact,hunt_samples}, cost:{spent_usd,cap_usd,halted_on_budget}, timing:{started_at,finished_at,duration_seconds|null,phase_timings:{}}, outcome:{execution_status,coverage_status,coverage_degraded_reasons:[],hunt_halted,agents_total,agents_incomplete}, findings:{counts:{sev→int},total}, redaction:{enabled,masked}?}`. `config.hash` = `"sha256:"+sha256(json(sorted subset of config keys))[:16]`.

## Verification set (verification.py — trailing `\n`, atomic)
- `candidate_manifest.json`: `{schema_version:1,revision,repo,raw_count,candidates:[{id:"CAND-<digest[:24]>",finding:<asdict Finding, stable_identity=digest, duplicate_of=null, cluster_id=id, from_confirmed=false, verification_status="unresolved">,provenance:[{source,source_agent,source_id,title,location,root_cause,entry_point}]}]}`. Non-git revision = `"tree-sha256:<hash of sorted source files>"`.
- `verification_decisions.json`: JSON array of decisions; each needs `candidate_id,verdict∈{supported,rejected,unresolved},rationale(non-empty),unresolved_questions:[str](empty if supported),entry_point(matches cited handler if supported),evidence:[{path,start_line,end_line}]`.
- `verification_reconciliation.json`: `{schema_version:1,complete,errors:[str],counts:{supported,rejected,unresolved},results:[{candidate_id,status,reason,record|null}],throughput:<metrics|null>}`.
- `verification_metrics.json`: `{candidates,attempted,accepted_decisions,incomplete,validation_failures,seconds,accepted_decisions_per_minute,verdict_counts:{supported,rejected,unresolved},attempts:[...]}`.
- `verification_candidate_%03d.json`: `{candidate_id,accepted,decision,validation_errors:[],stopped_reason,seconds}`.
- `artifact_manifest.json`: JSON **array**; each `{candidate_id,path("poc/…"|"exploit_tests/…"),kind("poc"|"test"),status:"authored"}` or `{candidate_id,kind:"deferred",reason}`. Engine writes `[]` at Phase-3 init.

## sbom.cdx.json (CycloneDX 1.5)
`{bomFormat:"CycloneDX",specVersion:"1.5",version:1,metadata:{tools:[{vendor:"vhlocal",name:"sbom"}],component:{type:"application",name:<repo basename|"application">},timestamp?},components:[{type:"library",name,purl,properties:[{name:"vhlocal:ecosystem",value:<eco>}],group?,version?,licenses?:[{license:{name}}]}]}` sorted by (ecosystem,name.lower,version). `purl=pkg:<type>/[group/]name[@version]`. Ecosystems parsed: `requirements*.txt`→pypi, `pyproject.toml`→pypi, `package.json`→npm, `go.mod`→golang, `pom.xml`→maven, `Gemfile.lock`→gem, `Cargo.toml`→cargo, `composer.json`→composer. Summary embedded in findings.json: `{total,by_ecosystem:{eco→int},components:[{name,version,ecosystem,license,group}]}`.

## Per-target ledger (`$VHLOCAL_LEDGER_DIR/<slug>.json`)
slug = `"<basename>-<sha1(resolved_path)[:8]>"`. `{target,updated,runs_recorded:[run_id],findings:[{key,canonical_cwe,family,title,location,severity,first_seen:{run,model,date},last_seen:{...},confirmed_in:[run_id],confirmed_count,cross_family,status("open"|"fixed"|"regressed"),confidence("provisional"|"confirmed"|"reliable")}]}`. `load_ledger` injects `summary` + `slug`. Confidence: reliable if confirmed_count≥3 or (≥2 & cross_family); confirmed if ≥2 or cross_family; else provisional. Only substantiated non-dup findings enter; idempotent by run_id. `ledger_key`: sink → `"<normalized_family>:<file>:<func>"`; logic/authz (no func) → `"<raw_cwe>:<file>:@<line//20>"`.

## applications.json (`<ledger_dir>/../applications.json`)
`{slug: {slug,name,repo,created,updated}}`; hidden entry `{slug,hidden:true}`. slug = same `membank` slug. Valid slug `^[A-Za-z0-9._-]+$` and no `..`.

## threat_model.md
Model-authored markdown; engine parses ONE machine-readable structure: a `Hunt targets` JSON array — first ```json fence (or greedy `[...]`) parsing to a list of objects each with `paths` or `subsystem`; per-object `{id,subsystem,paths:[],threat,cwe_class,priority}`. Parse failure tolerated (→ `[]`; hunt uses recon partitions). Parsed targets add Phase-2 partitions (recorded in `threat_model_partitions`).

## Deterministic tables the port MUST replicate exactly
See data-model.md for the full tables: `normalize_text` punctuation map; the `_FAMILIES` CWE-normalization table (family key, canonical name, canonical CWE, baseline severity, members); the severity tier order and the `_GATED` "-1 tier on precondition" regex; the `root_cause_key` fingerprint construction; and the lifecycle matching key precedence and algorithm. These are honesty-critical (Principle I/II) and must be byte-for-byte behavior-compatible, validated by tests against the Python output.

## Acceptance
Each artifact validates against the same schema/consumer that accepts today's output; existing on-disk reports (possibly missing newer fields) are read tolerantly (SC-004, FR-028). Deterministic layers produce identical classifications/labels/keys to the Python implementation over the `testdata/` fixtures.
