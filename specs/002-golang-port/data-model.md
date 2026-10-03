# Data Model: Port vhlocal to Go

**Feature**: 002-golang-port | **Date**: 2026-09-14

Entities the Go port must model, with their fields, key validation rules, relationships, and state transitions. Field-level JSON shapes and the exact on-disk layout live in [contracts/artifacts.md](./contracts/artifacts.md) and [contracts/http-api.md](./contracts/http-api.md); this file is the conceptual model plus the honesty-critical deterministic tables that MUST be replicated exactly.

## Entities

### ScanSpec
The full set of scan options; the input to `execute_scan`. Fields = the `run` CLI flags / POST /api/scans body (see contracts/cli.md, http-api.md). Defaults: `model="gpt-oss:120b"`, `host="http://localhost:11434"`, `num_ctx=131072`, `phases="all"`, `max_partitions=8`, `backend="ollama"`, `max_output_tokens=32768`, `hunt_samples=1`, `enforce_coverage=true`, `iac_lens=true`, `sweep_mode="deterministic"`, `quality_strictness="balanced"`, all per-role/booleans off/null. **Validation**: `repo` required + existing dir + inside allow-roots (server); `out` inside allow-roots; `num_ctx>0`; `max_partitions>0`; `phases` parses via `select_phases` (valid keys `1,1t,2,2b,3,3d,4`). **Relationships**: serialized into `Job.spec` and re-embedded in `scan_meta.meta`. **Precedence** when resolving knobs: built-in default < profile < explicit flag.

### RunRecord → scan_meta.json
Engine-observed facts (Principle I: authoritative over model prose). Field order & defaults:
`started_at(0.0), finished_at(0.0), repo(""), results_dir(""), model(""), verify_model(null), host(""), num_ctx(0), max_partitions(0), phases_requested([]), phases_completed([]), phases_skipped([]), phase_timings({}), partitions([]), partition_source(""), partition_fallback(false), partition_parse_error(""), partition_collapsed(false), coverage_partitions_added([]), coverage_files_added([]), coverage_uncovered_remaining([]), threat_model_partitions([]), vuln_classes([]), agents([{label,phase,model,turns,stopped_reason}]), usage({}), cancelled(false), engine_version(""), tool_envelope([]), bash_enabled(false), git_commit(""), git_branch(""), git_dirty(false), seeded_from_prior(""), aborted(""), scan_tag(""), recon_model(""), reproduce_model(""), ledger(false), redact(false), remediate(false), max_budget_usd(0.0), hunt_samples(1), iac_lens(true), budget_spent_usd(0.0), budget_halted_reason(""), hunt_halted_reason(""), quality_strictness("balanced")`.

### Finding
A candidate or confirmed vulnerability. Fields (declaration order; `to_dict` appends `potential_severity`):
`id, title, severity("Unrated"), severity_rank(7), cwe, location, entry_point, data_flow, status(raw model claim), poc, exploit_test(raw model claim), fix, source, source_id, verification_status, verification_reason, verification_record({}), stable_identity(sha256), duplicate_of(null), root_cause_key, cluster_id, poc_status, test_status, validation_method, finding_state, assessment, classification("hypothesis"), candidate_key, hypothesis_reason, assessment_reason, description, exploitability, reference, cve(always CVE-N/A for first-party), normalized_cwe, cwe_family, canonical_name, normalized_severity, reported_severity, finding_lifecycle, votes(0), vote_samples(0), from_confirmed(false), assessment_inherited(false), quality_checks([{name,status,reason}])`.
**Vocabulary**: `test_status∈{not_run,passed,failed}`; `validation_method∈{static_reasoning,dynamic_execution}`; `finding_state∈{statically_supported,dynamically_confirmed,unresolved}`; `poc_status∈{authored,none}`; `assessment∈{supported,unresolved}`; `classification∈{hypothesis,statically_supported,reviewed}`. **Rule**: model claims (`status`,`exploit_test`) kept verbatim and distinct from harness-derived state — never conflate reasoning with execution (Principle I).

### Job
Server-side scan unit. Fields per contracts/http-api.md. **Status FSM**: `queued → running → {done|failed|cancelled|interrupted}`. `queued`+cancel → `cancelled` immediately (emits `scan_done`). On process restart, `queued`/`running` → `interrupted` (`error="server restarted while job was active"`), never re-run (Principle VI). One FIFO worker; `busy` = one in-flight job.

### CoverageLedger → coverage_ledger.json
The coverage denominator (Principle II). `{total,reviewed,not_reviewed,complete,counts,entries:[{method,path,file,line,subsystem,disposition,evidence}]}`. Disposition∈`{finding_emitted,reviewed_no_issue,covered_by_parent_analysis,excluded_with_reason,not_reviewed}`. `complete = total>0 && not_reviewed==0`. **Built by** the deterministic entry-point enumerator (see §Enumeration) — AST-derived routes are the denominator; a run cannot be `complete` while any route is `not_reviewed`.

### RunStatus (three orthogonal axes — Principle II)
`{execution_status∈{aborted,cancelled,complete,partial,incomplete,unknown}, coverage_status∈{degraded,complete,partial}, coverage_degraded_reasons:[str], validation_mode∈{static_reasoning,dynamic_execution}}`. **No axis derived from another**; `validation_mode=dynamic_execution` only when `bash_enabled` (never by default). Degradation always carries reasons.

### Ledger (membank) & Application
Per-target cross-run memory and the application registry. Schemas in contracts/artifacts.md. Ledger key precedence and confidence tiers below. Application slug = `<basename>-<sha1(resolved_repo)[:8]>`.

### Report (index row), Profile, ModelInfo, ActivityEvent, SBOM, Manifests, VerificationRecord
Index/summary and auxiliary entities; schemas in the contracts. Profiles carry only the 18 allowed *structural* keys and never model/host/backend.

## Honesty-critical deterministic tables (replicate exactly)

### normalize_text() punctuation map
Applied before ANY regex over model output. Map: hyphens/dashes `U+2010,2011,2012,2013,2014,2015,2212 → "-"`; spaces `U+00A0,2007,2009,202F → " "`; quotes `U+2018→'`, `U+2019→'`, `U+201C→"`, `U+201D→"`. Nothing else altered. (U+2011 nbhyphen silently broke partition parsing — load-bearing.)

### CWE normalization — `_FAMILIES` (family key, canonical name, canonical CWE, baseline severity, members)
First family wins for a CWE in multiple families (`setdefault`).

| key | canonical name | canonical | baseline | members |
|---|---|---|---|---|
| code-injection | Code Injection | CWE-94 | High+ | 94,95,96 |
| template-injection | Server-Side Template Injection | CWE-1336 | High+ | 1336,917 |
| deserialization | Insecure Deserialization | CWE-502 | High+ | 502 |
| command-injection | OS Command Injection | CWE-78 | High+ | 78,77 |
| sql-injection | SQL Injection | CWE-89 | High | 89 |
| nosql-injection | NoSQL Injection | CWE-943 | High | 943 |
| xxe | XML External Entity (XXE) | CWE-611 | High | 611,827,776 |
| path-traversal | Path Traversal | CWE-22 | High | 22,23,36,73 |
| ssrf | Server-Side Request Forgery | CWE-918 | High | 918 |
| mass-assignment | Mass Assignment | CWE-915 | High | 915 |
| xss | Cross-Site Scripting | CWE-79 | Medium | 79,80,83,116 |
| open-redirect | Open Redirect | CWE-601 | Low | 601 |
| privilege-escalation | Privilege Escalation | CWE-269 | High | 269,266,267,250,648 |
| missing-auth | Missing Authentication | CWE-306 | High | 306,287,288,294,302 |
| access-control | Broken Access Control | CWE-284 | High | 284,285,639,862,863,638,1220,807 |
| weak-auth | Weak Authentication / Credential Handling | CWE-640 | Medium | 640,620,521,522,308,384 |
| weak-random | Insufficient Randomness | CWE-330 | Medium | 330,338,331,337,340 |
| weak-crypto | Weak Cryptography | CWE-327 | Medium | 327,326,328,916,759,760 |
| hardcoded-secret | Hard-coded Secret | CWE-798 | Medium | 798,321,259,260,547 |
| race-condition | Race Condition (TOCTOU) | CWE-362 | Medium | 362,367,364,366,543 |
| cors | CORS Misconfiguration | CWE-942 | Medium | 942,346 |
| rate-limiting | Missing Rate Limiting | CWE-799 | Low | 799,307 |
| resource-exhaustion | Uncontrolled Resource Consumption | CWE-400 | Medium | 400,770,834,1050 |
| timing | Observable Timing Discrepancy | CWE-208 | Low | 208,203,1254 |
| csrf | Cross-Site Request Forgery | CWE-352 | Medium | 352 |
| transport | Improper Transport / Certificate Handling | CWE-319 | Medium | 319,295,297,311,523 |
| info-disclosure | Sensitive Information Exposure | CWE-200 | Medium | 200,201,209,215,532,538,213 |

Keyword fallback `_FAMILY_WORDS` when no CWE: xxe, ssti, sql/nosql, pickle/deser, open redirect, path/directory traversal, command inj/os command, eval, ssrf, xss.

### Severity tiers & "-1 tier on precondition"
Tier order most→least: `Critical, High+, High, Medium, Low, Informational`. `normalized_severity(cwe, gated_text)` = family baseline; if `gated_text` matches `_GATED`, drop one tier (clamp to Informational). `_GATED` = `requires? .*(token|credential|auth|login|session)|internal[- ]?ops|ops[-_ ]?admin|x-internal-token|_wrk_gate|authenticated (user|caller|api)`. `gated_text` = join of `exploitability,data_flow,entry_point,status,title`. Consolidate label map: critical→Critical, high+→High+, high→High, medium/moderate→Medium, low→Low, informational/info→Informational; unknown rank 7, default label `Unrated`; `_sev_key` matches longest key substring. `cve` always the fixed `CVE-N/A` string for first-party findings.

### root_cause_key fingerprint (line-number-free)
`"<family>:<file>:<func>:<flowsig>"` where family = normalized family key (or keyword fallback); file = basename of first file token; func = last function-call name in location/data_flow lowercased (the sink); flowsig = comma-joined sorted set of attacker-input param names (minus stopwords). Degraded fallback (no file): `"<family>::<title_signature>"`. Empty string disables dedup for that finding.

### Finding lifecycle (Mode A reconciliation — deterministic, no model)
Match key precedence: (1) `source-v1:<stable_identity>` if present; (2) family-normalized `root_cause_key` (leading CWE rolled to canonical family CWE, `file:func:flowsig` tail kept); (3) `cwefile:<normalized_cwe|CWE-n>:<basename>`; (4) `""` (unmatchable). Algorithm: find most-recent strictly-earlier prior report of same resolved repo; current key in prior keys → `persisting`; in prior `fixed_keys` → `regressed`; else `new`. Duplicates inherit cluster canonical's state. Prior keys absent now → recorded `fixed`. Schema-change guard: current uses `stable_identity` but prior didn't → neutral baseline `comparison_status:"identity_schema_changed"`, all counts 0. Block canonical fields `not_observed`(supersedes `fixed`), `reappeared`(supersedes `regressed`), with deprecated aliases kept.

## Entry-point enumeration (parity risk — see research R16)
AST-based in Python (`inventory.py`): FastAPI (`@app.get`, `APIRouter`, `include_router` prefixes) + Flask (`@app.route`, blueprints); non-Python entry points are a documented limitation. The Go port re-implements this recognition to produce identical routes, dispositions, and partition-fallback synthesis; validated against `testdata/` fixtures. This is the coverage denominator, so fidelity here is honesty-critical (Principle II).

## Provenance (Principle IV) captured per AI call
Provider/backend, endpoint (secrets redacted), requested model + provider-returned model id, num_ctx/sampling/turn+token limits, tool envelope, phase/prompt identity, target git revision, per-phase attribution (recorded in RunRecord.agents, attribution block, run_manifest.models/transport/config.hash). Secrets (API keys) never written anywhere.
