# Engineer-ready Spec Kit command

Paste the following command into the engineering agent from the `vhlocal-go`
repository. This is specification input, not an executed Spec Kit workflow; no
feature branch or active feature pointer was changed when preparing the handoff.

```text
/speckit-specify Restore complete, usable scan-to-report workflows in vhlocal-go and close the application integration gaps with the Python reference in ../vhlocal.

Read docs/engineering/2026-09-17-handoff.md and docs/engineering/2026-09-17-evidence.json first. Treat the handoff's observed facts, confirmed contract mismatches, and unverified hypotheses as distinct. Review the prior audit changes rather than assuming they establish full parity. Preserve existing uncommitted work, scan history, reports, registry names, and ledger data.

Problem and desired outcome

The operator reports that Scans and Apps do not populate, threat reports and SBOMs are inaccessible, not every phase finishes, and the consolidated report is poor. A usable application must let an operator launch and follow a scan, find the resulting application and history after restart, inspect accurate phase outcomes, open threat/SBOM material, and read a useful evidence-based report. A partial scan must remain accessible and clearly explain what was completed, skipped, deferred, failed, or unresolved.

Current evidence to reproduce

At handoff, the local Go API returns 8 scan jobs and 8 reports. The latest job is 52331b0a1cf3, with report vc-claude-code-seeded-v2-logistics-dispatch-fastapi_VULNHUNT_RESULTS_gptoss120b_2026-09-17-003627. Its queue status is done, but its report says partial/degraded. Phases 2b and 3 did not complete. There are 140 candidates: 10 supported, 7 rejected, 123 unresolved, with 98 missing decisions. Verification records 72 tool_repair exits and 26 max_turns exits. Phase 3 authored 10 PoCs and 6 tests, but six test bindings fail structural validation. Threat-model and SBOM files both exist and return HTTP 200; the SBOM has 21 components. Applications list/detail return bare registry fields rather than the summary/history data the shipped UI expects. The running executable matched the on-disk binary at inspection. Do not diagnose all symptoms as missing files, no scanning activity, or a stale process.

Create one feature specification with prioritized user stories, testable requirements and measurable acceptance criteria covering the following outcomes. Separate established requirements from implementation choices in the later plan.

P1 — Scans are visible and reliable

An operator can see existing and newly queued/running/completed/partial/failed/cancelled/interrupted scans, select a scan, inspect progress and evidence, and reach its report. History survives service restart and refresh. Loading, empty, disconnected, malformed-response and error states are distinguishable; failures cannot appear as an empty successful list or endless loading. Reproduce the user's failure in the actual shipped UI before choosing a fix. Cover the root UI and React /app UI; explicitly inventory any other supported entrypoints. Existing persisted job shapes and older reports must not crash the page. Polling and event-stream reconnects must preserve coherent state without duplicate jobs or false completion.

P1 — Applications aggregate their real history and artifacts

Every analyzed repository is discoverable as an application, including scans with ledger disabled and reports created before the fix. Application summaries and details include the fields needed by the UI: name, repository, scan counts/history, latest report/time/outcome, supported and unresolved counts, severity/coverage summaries, optional ledger information, and threat/SBOM availability. Match the Python reference's report/registry/ledger aggregation semantics. Preserve naming, forgotten-app behavior, and stable repository identity. App registration/discovery must not depend on opting into vulnerability tracking. Missing optional data must not prevent history or existing artifacts from being displayed.

P1 — Status reflects actual work

Queue termination, engine execution status, coverage status and validation mode must remain distinct. Per-phase progress comes from validated engine outcomes, not the current phase index or a done job flag. A partial run must never display all steps complete. Surface the reason for each incomplete phase and retain useful partial results. Preserve the distinctions between explicit unresolved review, missing decision, zero candidates after a valid hunt, failed hunt, authored artifact, deferred artifact and executed test. Restart, resume and regeneration must preserve those meanings and invalidate stale dependent results where appropriate.

P1 — Threat model, SBOM and generated material are accessible

When selected and generated, threat reports and SBOMs appear in the scan/report/application views and can be opened and downloaded. Existing on-disk files must become discoverable without rerunning the scan. Handle not requested, pending, available, generation failed, missing, unreadable and malformed states explicitly. Artifact-generation and parse failures must be visible. Selected threat/SBOM work must not silently disappear when another phase fails. Establish the intended relationship between threat analysis and deterministic dependency inventory from the Python reference and document it. Do not fabricate missing historical material or overwrite original scan evidence as a migration shortcut.

P1 — Verification and reproduction recover from actionable failures

Use saved traces to categorize missing decisions and failed tool submissions. Improve source-context access, tool/schema compatibility and actionable validation feedback. Give candidates bounded repair opportunities, preserve accepted work, and report unresolved outcomes with useful reasons when the allotted work cannot establish a conclusion. Explain and measure retry/turn limits. Support evidence-based authorization/logic review without requiring an injection-style syntactic sink where the Python reference does not require one. Do not weaken attacker-control, precondition, defense, impact, revision or exact-evidence requirements merely to improve completion metrics.

Reproduction assignments must bind only to supported candidates. Every such candidate receives registered authored material or a specific deferral; invalid headers, locations, registrations and missing files get bounded corrective feedback. Keep candidate IDs stable and explain failures that remain. Do not call authored material executed, accept print-only tests as proof, or run target code/exploits automatically. Preserve the current failed output for regression analysis.

P2 — Reports are useful to a reviewer

Deliver coherent human-readable Markdown/HTML and UI reports derived from canonical evidence. Include scope, run/coverage/phase limitations, a clear supported-findings summary, and separately identified rejected/unresolved candidates. A supported finding includes its source location and relevant evidence, entry point, attacker control and flow, preconditions, reviewed defenses, security impact, rationale, remediation, and links/status for reproduction material or deferral. Make missing information explicit. Provide navigation to threat analysis, SBOM, coverage and sweep leads. Syntactic leads must not become confirmed findings. Candidate totals must not be presented as confirmed vulnerability totals. Compare representative output with Python and have a reviewer assess usefulness; file existence or report length is not a quality criterion. Keep deterministic reporting while improving its content and organization.

P2 — Supported options and work limits behave honestly

Trace relevant settings from each UI/CLI request through effective engine configuration and persisted metadata. Honor supported settings or reject unsupported ones explicitly; never silently ignore an option. Include threat model, ledger, role model/provider settings, hunt sampling and partition/coverage behavior. Explain why a request for max_partitions=8 produced 24 partitions in the saved scan, and document whether the control is a cap or a coverage-driven starting point. Make the resulting work and bounded recovery visible so a broken run does not silently expand into hours of retries.

Acceptance requirements

1. Real browser tests against the Go server show Scans and Apps populated from seeded persisted data, including at least two applications, multiple reports per application, a ledger-disabled application, and an older report. Repeat after refresh and server restart. No uncaught error or silent empty-state fallback is acceptable.
2. An offline scripted scan traverses the public launch/status/report workflow, then appears in Scans, Reports and its application. Verify response field semantics used by the UI, not just HTTP success or key presence.
3. A fixture representing the saved partial run displays Phase 2b and Phase 3 as incomplete, preserves its supported/unresolved/rejected distinctions, exposes the threat report and 21-component SBOM, and never labels every step complete.
4. Positive and negative artifact fixtures cover requested/disabled/missing/malformed threat/SBOM material; valid authored material, explained deferral, wrong candidate/location, missing files and failed repair. Unknown and failed states remain visible after reload and regeneration.
5. Controlled model fixtures demonstrate recovery from at least one rejected verification submission and one invalid reproduction submission. Exhausted recovery produces a bounded, explained incomplete/unresolved outcome. Report attempt and failure counts; do not require fabricated confirmation or arbitrary all-supported output.
6. Existing audit protections remain covered: distinct candidate sites, exact source and revision checks, complete reasoning, containment, no empty-output completion, supported-only reproduction, independent Python-reference contracts, deterministic sweep/reporting, and resume/regeneration validity.
7. A representative supported finding exposes all review details listed above, with explicit unknowns where appropriate; unsupported cases cannot be mistaken for confirmed findings. Browser, Markdown, HTML and machine-readable outcomes agree.
8. Supply the actual built frontend/backend provenance used for acceptance, plus a concise behavior matrix against Python showing matches, documented approximations and remaining gaps. A passing Go suite or a Go-generated golden alone is insufficient.
9. Use saved outputs and offline fixtures first. Define a bounded live-model validation plan for the operator; do not automatically launch another multi-hour scan or execute generated exploit material. Full live detection parity remains an empirical acceptance question, separate from these integration contracts.

Deliver the specification and acceptance scenarios, then use the normal Spec Kit planning/task workflow to produce dependency-ordered engineering work and a validation plan. Prioritize restoring data visibility and truthful status before spending another long scan on model tuning. Keep implementation details, source-file investigation notes and test design in the plan/handoff rather than presenting them as end-user requirements. Avoid a broad UI redesign, cosmetic-only fixes, blanket rollback of the audit protections, or claims that this bounded feature establishes complete scanner parity.
```
