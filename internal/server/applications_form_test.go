package server

import (
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"testing"

	vhlocal "vhlocal"
)

// T054 (FR-024/025; SC-010 shipped-asset half): the EMBEDDED main UI carries the
// application-access behaviors — keyboard-activatable rows/cards, the
// `#applications?app=<slug>` deep link written on open and parsed by the hash
// readers, scrollIntoView on the detail pane, a selection sequence guard, the
// pinned 100-rows/page bound, error+retry (never indefinite loading), and the
// server-side artifact selection with its disclosure — while the list/table
// controls and management actions are preserved.
func TestShippedApplicationsContract(t *testing.T) {
	web, err := fs.Sub(vhlocal.WebFS, "vhlocal/web")
	if err != nil {
		t.Fatal(err)
	}
	b, err := fs.ReadFile(web, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	must := map[string]string{
		// keyboard parity: both layouts render the shared activation attributes
		"activation attrs":     `tabindex="0" role="button" onclick="openApplication(`,
		"keydown handler":      `onkeydown="appKey(event,`,
		"Enter/Space handling": `ev.key === 'Enter' || ev.key === ' '`,
		"table row activates":  `data-slug="${esc(a.slug)}"` + "\n        ${appActivate(a.slug)}",
		"card activates":       `class="card ai-appcard${a.slug===_appActive?' on':''}" data-slug="${esc(a.slug)}" ${appActivate(a.slug)}`,
		// deep link written on open, parsed by the hash readers, back restores the list
		"deep link written": `const want = '#applications?app=' + encodeURIComponent(slug);`,
		"history entry":     `history.pushState(null, '', want)`,
		"hash reader":       `function _hashParts()`,
		"hash app query":    `h.params.get('app')`,
		"back closes":       `else if (!slug && _appActive) closeApplication();`,
		"boot honors query": `navigate(VIEWS[_h0.view] ? _h0.view : 'home', _hashOpts(_h0));`,
		// visible pane
		"scrollIntoView": `host.scrollIntoView({block:'start', behavior:'smooth'})`,
		// stale guard
		"sequence guard": `const seq = ++_appSeq;`,
		"stale dropped":  `if (seq !== _appSeq) return;`,
		// bounded list (contracts/evidence-api.md "Bounds": 100 rows/page)
		"page bound": `const APPS_PAGE = 100;`,
		"page slice": `const page = all.slice(0, _appsShown);`,
		"show more":  `window.showMoreApps = function(){ _appsShown += APPS_PAGE; renderApps(); };`,
		// error + retry, never indefinite loading
		"detail retry": `Could not load application: ${esc(e.message)}`,
		"retry button": `onclick="openApplication('${escA(slug)}')">Retry</button>`,
		// artifact selection with disclosure; 404 ≠ error
		"selection used":   `const sel = (a.artifacts && a.artifacts[kind]) || null;`,
		"disclosure":       `older than the latest scan`,
		"explained absent": `unavailable: ${esc(sel.reason || 'no valid artifact')}`,
		"error≠absence":    `if (r.status === 404) return { status: 404, text: null };`,
		"tab retry":        `<button class="secondary" onclick="renderAppTab()">Retry</button>`,
		// preserved controls and management actions
		"layout toggle": `onclick="setAppsView('table')"`,
		"sortable":      `onclick="sortApps('${k}')"`,
		"bulk delete":   `onclick="deleteSelectedApps()"`,
		"rename":        `onclick="renameApplication(`,
		"forget":        `onclick="forgetApplication(`,
	}
	for name, needle := range must {
		if !regexp.MustCompile(regexp.QuoteMeta(needle)).MatchString(src) {
			t.Errorf("shipped index.html lacks %s: %q", name, needle)
		}
	}
	// The React client's report fetch must keep 404 distinct from 5xx (asserted on
	// the source, which the operator builds into /app; skipped if the tree is absent).
	apiTS := filepath.Join("..", "..", "web-react", "src", "lib", "api.ts")
	if ab, err := os.ReadFile(apiTS); err == nil {
		for _, needle := range []string{
			`reportFetch: async (id: string, path: string, signal?: AbortSignal): Promise<ReportFetch>`,
			`if (r.status === 404) return { status: 404, text: null };`,
			`return { status: r.status, text: null, error:`,
		} {
			if !regexp.MustCompile(regexp.QuoteMeta(needle)).Match(ab) {
				t.Errorf("web-react api.ts lacks %q", needle)
			}
		}
		page, _ := os.ReadFile(filepath.Join("..", "..", "web-react", "src", "pages", "Applications.tsx"))
		for _, needle := range []string{`useSearchParams`, `const APPS_PAGE = 100;`, `tabIndex={0}`, `role="button"`, `Retry`, `older than the latest scan`, `ctl.abort()`} {
			if !regexp.MustCompile(regexp.QuoteMeta(needle)).Match(page) {
				t.Errorf("web-react Applications.tsx lacks %q", needle)
			}
		}
	}
}
