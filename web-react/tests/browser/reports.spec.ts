import { test, expect, type Page } from "@playwright/test";
import { readFileSync, readdirSync } from "node:fs";
import { resolve } from "node:path";

// OPERATOR-RUN. These specifications are not part of the offline Go suite and are recorded
// as `machine_executed` only when an operator actually runs them. A green offline suite is
// not evidence of browser quality (feature 016, SC-008, C-P36).
//
// Feature 016 (T098): the fixtures now carry the `presentation` projection, so the specs
// exercise the redesigned surfaces — issues to fix, the five reader sections, the separated
// Needs review list — and one spec pins the pre-016 fallback, which must keep working.

const fixtureRoot = resolve(process.cwd(), "../testdata/diagrams");
const rows = ["scan-a", "scan-b"].map(id => ({ id, name: id, repo: `/fixture/${id}`, model: "offline", findings: 1, hypotheses: 1, severities: { High: 1 }, created: 1, size: 100, chains: 0, has_report: true }));

// The feature-015 model, which the viewers still render for a report saved before 016.
function legacyModel(id: string) {
  const f = { id: "F1", title: `${id} SQL injection`, severity: "High", location: "app.py:2", cwe: "CWE-89", evidence: [{ path: "app.py", start: 2, end: 2, quote: "execute(query)" }], fix: "Use parameters", reproduction: { status: "not executed" } };
  return { version: 1, status: { execution: "partial", coverage: "incomplete", validation_mode: "static" }, summary: { narrative: `${id}: One supported issue; coverage is incomplete.`, words: 9, leading: [], limitations: [] }, counts: { supported: 1, rejected: 0, unresolved_explicit: 1, unresolved_failed: 0, total_candidates: 2, remediation_groups: 1, source_review: { completed: 1, total: 2 } }, severity_supported: { High: 1 }, severity_candidates: { High: 2 }, index: [{ ...f, anchor: "finding-F1", surface: "GET /query", evidence_status: "evidence_captured", action: f.fix }], findings: [f], groups: [], appendix: { rejected: [], unresolved_explicit: [{ id: "U1", title: "Uncertain issue", location: "app.py:9", reason: "insufficient evidence" }], unresolved_failed: [] } };
}

// The feature-016 model: the same records, plus the reader-facing projection every surface
// renders. No surface recomputes any of it.
function model(id: string) {
  const base = legacyModel(id);
  return {
    ...base,
    presentation: {
      version: 1,
      identity: { application: id, scan_date: "2026-09-30T00:39:35Z", timezone: "UTC", revision: "abcdef123456" },
      opening: {
        risk_summary: `${id}: this scan established 1 issue to fix. Each issue below names the affected code, why it matters, and the change to make.`,
        scope_sentence: "Review scope: execution Incomplete; 1 of 2 entry points completed — places where the application accepts input; method Source-code analysis, so the application itself was never executed.",
        words: 42,
      },
      scope: { execution: "Incomplete", coverage_completed: 1, coverage_total: 2, coverage_exposed: 2, coverage_known: true, method: "Source-code analysis", gap_sentence: "Review of the remaining 1 was not completed; these results cover the reviewed code.", entry_point_gloss: "places where the application accepts input" },
      counts: { issues_to_fix: 1, severity: { Critical: 0, High: 1, Medium: 0, Low: 0, Informational: 0, Unrated: 0 }, needs_review: 1, needs_review_inconclusive: 1, needs_review_incomplete: 0, dismissed: 0, detections: 1, candidates_examined: 2 },
      priority: [{ ref: "ISSUE-001", issue: `${id} SQL injection`, severity: "High", affected_area: "GET /query", action: "Pass the untrusted value as a bound query parameter instead of concatenating it into the statement text." }],
      issues: [{
        ref: "ISSUE-001", title: `${id} SQL injection`, severity: "High", family: "sql-injection", cwe: "CWE-89",
        canonical_name: "SQL Injection", detection_count: 1,
        members: [{ finding_id: "F1", role: "primary", entry_point: "GET /query", severity: "High" }],
        locations: [{ file: "app.py", lines: "2", entry_point: "GET /query", citation_count: 1, available: true }],
        entry_points: ["GET /query"],
        what_we_found: "The query parameter reaches execute unsanitized.",
        why_it_matters: "An attacker can read and write arbitrary rows.",
        attacker_control: "the q query parameter",
        how_to_fix_it: { provenance: "recorded", steps: ["Pass the untrusted value as a bound query parameter instead of concatenating it into the statement text."], checks: ["Confirm the statement text is constant for every input on this path."], label: "Recorded during the review of this finding. Nothing here has been implemented or tested.", mechanism: "untrusted input is concatenated into a SQL statement" },
        how_to_check_the_fix: ["Confirm the statement text is constant for every input on this path."],
        evidence: [{ path: "app.py", start: 2, end: 2, quote: "execute(query)" }],
      }],
      review_items: [{ ref: "REVIEW-001", kind: "inconclusive", title: "Uncertain issue", location: "app.py:9", what_is_unresolved: "The review examined this and reached no decision either way.", next_step: "Read the cited code and decide: nothing about this allegation has been established or refuted.", provisional_severity: "Medium" }],
      dismissed: [],
    },
  };
}

// API responses are synthetic and never reach jobs, providers, or operator reports.
async function fixture(page: Page, diagram = "graph TD\nA[\"Client\"] --> B[\"Service\"]", modelFor: (id: string) => unknown = model) {
  await page.route("**/api/**", async route => {
    const u = new URL(route.request().url());
    if (u.pathname === "/api/reports") return route.fulfill({ json: { reports: rows } });
    const m = u.pathname.match(/^\/api\/reports\/(scan-[ab])\/(files|file)$/);
    if (m) {
      const id = m[1];
      if (m[2] === "files") return route.fulfill({ json: { root: `/fixture/${id}`, files: ["report_model.json", "SCAN_REPORT.md", "threat_model.md"].map(path => ({ path, size: 100 })) } });
      if (u.searchParams.get("path") === "report_model.json") return route.fulfill({ json: modelFor(id) });
      const body = u.searchParams.get("path") === "threat_model.md" ? `# Threat model\n\nNarrative survives diagram errors.\n\n\`\`\`mermaid\n${diagram}\n\`\`\`` : `# ${id} report\n\nExecution diagnostics for ${id}.`;
      return route.fulfill({ contentType: "text/plain", body });
    }
    return route.fulfill({ json: { applications: [], ledgers: [], jobs: [], events: [], profiles: [], models: [], busy: false, defaults: {}, phases: [], allow_roots: [] } });
  });
}

for (const surface of ["main", "react"] as const) {
  const url = (id: string) => surface === "main" ? `/#reports?open=${id}` : `/app/reports?open=${id}`;
  const summary = (page: Page) => page.locator(surface === "main" ? "#execSummary" : '[data-testid="executive-summary"]');

  test(`${surface}: opening, issues to fix, filters, keyboard and evidence`, async ({ page }) => {
    await fixture(page);
    await page.goto(url("scan-a"));

    // The opening leads with the issue count and the scope note, not with candidate totals.
    await expect(summary(page)).toContainText("1 issue to fix");
    await expect(summary(page)).toContainText("Review scope: execution Incomplete");
    await expect(summary(page)).not.toContainText("candidates total");

    const search = page.getByRole("searchbox", { name: "Search issues" });
    const row = page.locator('tr[data-anchor="issue-001"]');
    expect((await summary(page).boundingBox())!.y).toBeLessThan((await search.boundingBox())!.y);

    // Filtering names the displayed subset and keeps the full total reachable.
    await search.fill("no such issue");
    await expect(row).toBeHidden();
    await expect(page.getByText(/issues to fix in the full report|No issue matches this filter/)).toBeVisible();
    await search.fill("");

    // Keyboard activation opens the issue, which carries the five reader sections.
    await row.focus();
    await page.keyboard.press("Enter");
    const detail = page.locator("#issue-001");
    await expect(detail).toHaveAttribute("open", "");
    for (const section of ["What we found", "Why it matters", "Where it is", "How to fix it", "How to check the fix"]) {
      await expect(detail).toContainText(section);
    }
    await expect(detail).toContainText("Nothing here has been implemented or tested.");
    await expect(detail).toContainText("execute(query)");

    // A pre-016 deep link still resolves, inside the issue that reports the detection.
    await expect(page.locator("#finding-F1")).toHaveCount(1);

    // Needs review is a separate section and never a vulnerability.
    await expect(page.getByText("Uncertain issue")).toHaveCount(1);
    await expect(page.getByText(/severity proposed, not established/)).toHaveCount(1);
  });

  test(`${surface}: a report saved before this feature still renders`, async ({ page }) => {
    await fixture(page, undefined, legacyModel);
    await page.goto(url("scan-a"));
    // The feature-015 surface, unchanged: supported totals and the per-detection index.
    await expect(summary(page)).toContainText("1 supported");
    await expect(page.locator('tr[data-anchor="finding-F1"]')).toHaveCount(1);
    // And no redesigned section is fabricated for it.
    await expect(page.locator('tr[data-anchor="issue-001"]')).toHaveCount(0);
  });

  test(`${surface}: a late response cannot replace the selected scan`, async ({ page }) => {
    await fixture(page);
    let unblock!: () => void; let requested!: () => void; const waiting = new Promise<void>(r => { requested = r; });
    const hold = new Promise<void>(r => { unblock = r; });
    await page.route("**/api/reports/scan-a/file?path=report_model.json", async route => { requested(); await hold; await route.fulfill({ json: model("scan-a") }); });
    await page.goto(url("scan-a"));
    await waiting;
    await page.getByRole("cell", { name: "/fixture/scan-b", exact: false }).first().click();
    await expect(summary(page)).toContainText("scan-b:");
    unblock();
    await expect(summary(page)).not.toContainText("scan-a:");
  });

  test(`${surface}: readable at 375 CSS pixels`, async ({ page }) => {
    await page.setViewportSize({ width: 375, height: 800 });
    await fixture(page);
    await page.goto(url("scan-a"));
    await expect(summary(page)).toContainText("1 issue to fix");
    // No page-level horizontal overflow: long content wraps or scrolls inside its own box.
    const overflow = await page.evaluate(() => document.documentElement.scrollWidth - document.documentElement.clientWidth);
    expect(overflow).toBeLessThanOrEqual(1);
  });

  for (const file of readdirSync(fixtureRoot).filter(n => n.endsWith(".md"))) {
    test(`${surface}: diagram corpus ${file}`, async ({ page }) => {
      const markdown = readFileSync(resolve(fixtureRoot, file), "utf8");
      const diagrams = [...markdown.matchAll(/```mermaid\s*\n([\s\S]*?)```/g)].map(m => m[1]);
      await fixture(page, diagrams.join("\n```\n\n```mermaid\n"));
      await page.goto(url("scan-a"));
      if (surface === "react") await page.getByRole("tab", { name: "Threat model", exact: true }).click();
      await expect(page.getByText("Narrative survives diagram errors.")).toBeVisible();
      const settled = surface === "main" ? page.locator('[data-dgm-state="valid"], [data-dgm-state="repaired"], [data-dgm-state="error"]') : page.locator('[data-testid="diagram-error"], .mermaid-box svg');
      await expect.poll(() => settled.count()).toBeGreaterThan(0);
      await expect(page.locator('img[src="x"]')).toHaveCount(0);
    });
  }
}
