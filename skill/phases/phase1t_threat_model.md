# Phase 1t — Threat Model (PASTA)

You run **after recon (Phase 1) and before the hunt (Phase 2)**. Recon mapped the
*web/RPC* attack surface. Your job is to model the application as a whole and
decide **where the hunt should look** — including surfaces recon's entry-point
enumeration does not capture (syscall boundaries, parsers of untrusted data,
privileged operations, IPC, deserialization, memory-management interfaces).

You follow **PASTA** (Process for Attack Simulation and Threat Analysis). The
point is not a document — it is to reason from *what this application is* to *how
this class of application is attacked* to *which concrete code the hunt must
trace*. A beautiful threat model that yields no hunt targets is a failure.

## Inputs you have

- The recon output (`phase1_output.md`) — the enumerated web/RPC entry points.
- A dependency inventory (SBOM) is provided inline below, if present.
- The repository (read-only) — explore it with Grep/Glob/Read.

## Work through the PASTA stages

**Stage I — Objectives & assets.** In 2–4 sentences: what is this application,
what does it do, who runs it, and what are its **crown-jewel assets** (the data or
capability an attacker wants — secrets, host compromise, user data, funds, code
execution, sandbox escape)?

**Stage II — Technical scope.** Identify the **application archetype** explicitly
— e.g. *web service / REST API / CLI tool / language runtime / container or OS
sandbox / crypto library / parser or codec / message broker / device firmware /
ML pipeline / browser extension / IaC*. State the stack and note notable
dependencies from the SBOM. **The archetype is the key that unlocks the right
threats — name it precisely.**

**Stage III — Decomposition & Data Flow Diagram.** Identify the external actors,
the processes/components, the data stores, and — critically — the **trust
boundaries** (where data crosses from less-trusted to more-trusted: network→app,
guest→host, user→kernel, untrusted-input→parser, tenant→tenant). Produce a **Data
Flow Diagram** as a Mermaid `flowchart TD` in a ` ```mermaid ` fenced block. Mark
trust boundaries with `subgraph` blocks. Every untrusted-input edge crossing a
boundary is a hunt candidate.

The Mermaid MUST be syntactically valid — it is rendered directly, and a syntax
error shows the user an error instead of a diagram. Follow these rules exactly:
- **Always double-quote every node and subgraph label**, e.g. `A["HTTP request"]`,
  `C["misc device (/dev/foo)"]`, `subgraph TB1["User space"]`. Quoting is
  mandatory whenever a label contains a space, parenthesis, slash, colon, or any
  non-alphanumeric character — which is almost always, so just always quote.
- Use plain ASCII in labels: write `->` or `to`, not the `→` arrow; use a normal
  hyphen `-`, not a unicode dash.
- Node ids are short and alphanumeric (`A`, `B2`, `Sentry`); the human text goes
  in the quoted label, never in the id.
- Edges are `A --> B` or `A -->|"label"| B`. Do NOT put a trailing backslash on
  any line. Do NOT include `style`/`classDef`/`click` directives — nodes, edges,
  and subgraphs only.

**Stage IV — Threat analysis (archetype-driven).** Given the archetype from Stage
II, enumerate the threats that **matter for this class of software** — not a
generic OWASP list. Use your knowledge of how this kind of system is attacked. For
each: the threat, the STRIDE category, and the trust boundary it crosses.
Examples of archetype-specific reasoning:
- *container/OS sandbox* → guest→host escape via syscall-handler bugs, memory
  corruption in the emulated kernel, seccomp/ptrace bypass, resource exhaustion.
- *parser/codec* → memory corruption, infinite loops/DoS, injection via crafted input.
- *crypto library* → timing side channels, nonce/IV reuse, padding oracles, weak RNG.
- *web service* → injection, broken authz/IDOR, SSRF, deserialization, secrets.
- *message broker / queue* → poisoned-message handling, authz on topics, replay.

**Stage V — Weakness → target mapping (THIS DRIVES THE HUNT).** For each
high-value threat, locate the **concrete code** that realizes it: the file(s) or
directory(ies) where the untrusted input is handled or the dangerous operation
lives. Grep/Glob/Read to find them — do not guess paths. Assign each a likely
**CWE class** and a hunt priority.

**Stage VI — Attack modeling.** For the top 3–5 threats, one line each: the attack
path from entry to impact (how an attacker gets from the boundary to the asset).

## Output contract

Write **`threat_model.md`** with these sections, in order:

1. `## Application characterization` — Stages I–II (what it is, archetype, assets, stack).
2. `## Data flow diagram` — the Mermaid DFD (Stage III), then a short list of the trust boundaries.
3. `## Threats (PASTA)` — a table: `| # | Threat | STRIDE | Trust boundary | Attack path |` (Stages IV, VI).
4. `## Hunt targets` — **a fenced ` ```json ` block** and nothing else in that block: a JSON array where each element is
   `{"id": "TM-N", "subsystem": "<short name>", "paths": ["<repo-relative file or dir>", ...], "threat": "<one line>", "cwe_class": "CWE-NNN", "priority": "high|medium|low"}`.
   This block is parsed by the harness to add hunt partitions for surfaces recon
   missed. **Every path must exist in the repo (verify with Glob/Read). Cover the
   archetype-specific surfaces, not just the web entry points.**

If the application is a straightforward web service whose surface recon already
covers, that is fine — still emit the JSON (it will simply overlap recon and add
nothing). The failure mode to avoid is the opposite: an unusual target (a sandbox,
a parser, a runtime) where the real attack surface is code recon never enumerated,
and `Hunt targets` is left empty or web-only.
