import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

// Executes the shipped viewer function with a minimal host and delayed API.
// This tests response ordering, not DOM rendering or browser interaction.
test("a late main-viewer response cannot replace the selected report", async () => {
  const html = readFileSync(new URL("../../vhlocal/web/index.html", import.meta.url), "utf8");
  const start = html.indexOf("const _reportRenderSeq = new WeakMap();");
  const end = html.indexOf("window.viewReportFile =", start);
  assert.ok(start >= 0 && end > start);
  let release;
  const delayed = new Promise(resolve => { release = resolve; });
  const host = { innerHTML: "", querySelector: () => null, scrollIntoView() {} };
  const sandbox = { window: {}, WeakMap, $: () => host, esc: String, escA: String,
    api: url => url.includes("scan-a") ? delayed : Promise.resolve({ root: "scan-b", files: [] }),
    reportSummaryHTML: () => "", ledgerLinkHTML: () => "", findingsSectionHTML: () => "",
    chainsSectionHTML: () => "", appIntelSectionHTML: () => "" };
  vm.runInNewContext(html.slice(start, end), sandbox);
  const old = sandbox.window.openReport("scan-a");
  await sandbox.window.openReport("scan-b");
  assert.match(host.innerHTML, /scan-b/);
  release({ root: "scan-a", files: [] });
  await old;
  assert.match(host.innerHTML, /scan-b/);
  assert.doesNotMatch(host.innerHTML, /scan-a/);
});
