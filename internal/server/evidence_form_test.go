package server

import (
	"io/fs"
	"regexp"
	"strings"
	"testing"

	vhlocal "vhlocal"
)

// Feature 014 (FR-003/004/009, T020): the SHIPPED (embedded) main UI uses the new
// evidence endpoints, guards requests against cross-scan bleed, resolves the pane
// before awaiting, refreshes Artifacts and Log live (not only Prompts), and renders
// distinct evidence-state messages including "not recorded by this version".
func TestShippedMainUIEvidenceContract(t *testing.T) {
	web, err := fs.Sub(vhlocal.WebFS, "vhlocal/web")
	if err != nil {
		t.Fatal(err)
	}
	b, err := fs.ReadFile(web, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	for _, want := range []string{
		"/prompts?",           // new prompts endpoint (not file?path=prompts.jsonl)
		"/log?tail=",          // windowed log endpoint
		"AbortController",     // request cancellation
		"sel !== id",          // stale-response guard against the current selection
		"refreshFilesQuietly", // Artifacts refresh live
		"refreshLogQuietly",   // Log refresh live
		"not recorded by this version",
		"not_started", "running_no_files", "unavailable", // distinct state messages
		"id=\"logFollow\"", // controllable log following
	} {
		if !strings.Contains(src, want) {
			t.Errorf("shipped index.html lacks %q", want)
		}
	}
	if strings.Contains(src, "file?path=prompts.jsonl") {
		t.Error("shipped index.html still fetches the raw prompts.jsonl file")
	}
	if strings.Contains(src, "No prompts captured yet") {
		t.Error("shipped index.html still shows the reassuring 'not captured yet' message")
	}
	// Each evidence loader resolves the pane BEFORE its first await (FR-004).
	for _, fn := range []string{"loadFiles", "loadLog", "loadPrompts"} {
		re := regexp.MustCompile(`(?s)async function ` + fn + `\(id\) \{(.*?)\n\}`)
		m := re.FindStringSubmatch(src)
		if m == nil {
			t.Errorf("cannot locate %s", fn)
			continue
		}
		body := m[1]
		bi, ai := strings.Index(body, "$('tabbody')"), strings.Index(body, "await ")
		if bi < 0 || ai < 0 || bi > ai {
			t.Errorf("%s must resolve $('tabbody') before its first await (got body@%d await@%d)", fn, bi, ai)
		}
	}
}

// T079 (FR-029): the SHIPPED main UI labels a clamped prompt record as a stored
// preview and says the full text was not kept, so telemetry truncation is never
// read as the model having received truncated context. React carries the same
// wording (web-react/src/pages/Scans.tsx).
func TestShippedMainUILabelsStoredPreviewHonestly(t *testing.T) {
	web, err := fs.Sub(vhlocal.WebFS, "vhlocal/web")
	if err != nil {
		t.Fatal(err)
	}
	b, err := fs.ReadFile(web, "index.html")
	if err != nil {
		t.Fatal(err)
	}
	src := string(b)
	if !strings.Contains(src, "stored preview (8 KB clamp); full text not stored") {
		t.Error("shipped index.html must label a clamped record as a stored preview whose full text was not stored")
	}
	// The older wording said only "content clamped", which reads as model-context
	// truncation rather than a storage clamp.
	if strings.Contains(src, ">content clamped<") {
		t.Error("shipped index.html still carries the ambiguous \"content clamped\" label")
	}
}
