package verification

import (
	"encoding/json"
	"fmt"
	"strings"

	"vhlocal/internal/citation"
	"vhlocal/internal/consolidate"
)

// Submission / tool error codes (feature 015, C-C6/C-C7) beyond the citation codes.
const (
	EVerdict                = "E_VERDICT"
	ERationaleRequired      = "E_RATIONALE_REQUIRED"
	EFieldRequired          = "E_FIELD_REQUIRED"
	EEvidenceIDUnknown      = "E_EVIDENCE_ID_UNKNOWN"
	EEvidenceMismatch       = "E_EVIDENCE_MISMATCH"
	EEvidenceRequired       = "E_EVIDENCE_REQUIRED"
	ESupportedWithQuestions = "E_SUPPORTED_WITH_QUESTIONS"
	EInvalidCitation        = "E_INVALID_CITATION"
	ESubmissionRejected     = "E_SUBMISSION_REJECTED"
	EAmendmentLimit         = "E_AMENDMENT_LIMIT"
	EAmendmentCandidate     = "E_AMENDMENT_CANDIDATE"
	EAmendmentUnbound       = "E_AMENDMENT_UNBOUND"
	EUnknownTool            = "E_UNKNOWN_TOOL"
)

// Feedback is the structured error returned to the model for a rejected tool call.
type Feedback struct {
	Code       string        `json:"code"`
	Field      string        `json:"field,omitempty"`
	Received   string        `json:"received,omitempty"`
	Expected   string        `json:"expected"`
	Repairable bool          `json:"repairable"`
	Aids       citation.Aids `json:"aids"`
	Message    string        `json:"message,omitempty"`
}

// JSON renders the feedback as the tool result the model sees.
func (f Feedback) JSON() string {
	b, _ := json.Marshal(map[string]any{"error": f})
	return string(b)
}

// FromCitationError lifts a citation error into feedback.
func FromCitationError(e *citation.Error) Feedback {
	return Feedback{Code: e.Code, Field: e.Field, Received: e.Received, Expected: e.Expected, Repairable: e.Repairable, Aids: e.Aids, Message: e.Error()}
}

// ClassifySubmissionError maps a reconciliation/decision error to a code with the
// candidate's binding aids (handler span, route, file length) attached.
func ClassifySubmissionError(msg string, c Candidate) Feedback {
	aids := citation.Aids{}
	if c.Citation != nil && c.Citation.Binding != nil {
		aids = citation.AidsFor(*c.Citation.Binding)
	}
	fb := Feedback{Code: ESubmissionRejected, Expected: "a decision that satisfies the evidence contract", Repairable: true, Aids: aids, Message: msg}
	low := strings.ToLower(msg)
	switch {
	case strings.Contains(low, "verdict must be"), strings.Contains(low, "unknown verdict"):
		fb.Code, fb.Field, fb.Expected = EVerdict, "verdict", "one of supported | rejected | unresolved"
	case strings.Contains(low, "rationale is required"):
		fb.Code, fb.Field, fb.Expected = ERationaleRequired, "rationale", "a non-empty rationale"
	case strings.Contains(low, "review is missing "):
		fb.Code, fb.Field = EFieldRequired, strings.TrimPrefix(strings.TrimSpace(msg[strings.Index(low, "review is missing ")+len("review is missing "):]), "")
		fb.Expected = "a non-empty " + fb.Field
	case strings.Contains(low, "evidence_ids must reference"):
		fb.Code, fb.Field, fb.Expected = EEvidenceIDUnknown, "evidence_ids", "ids returned by capture_evidence in THIS session"
		if i := strings.LastIndex(msg, ": "); i >= 0 {
			fb.Received = msg[i+2:]
		}
	case strings.Contains(low, "requires cited source evidence"):
		fb.Code, fb.Field, fb.Expected = EEvidenceRequired, "evidence_ids", "at least one capture_evidence id covering the handler"
	case strings.Contains(low, "does not match the live source"):
		fb.Code, fb.Field, fb.Expected = EEvidenceMismatch, "evidence", "quotes captured by capture_evidence (never pasted or edited)"
	case strings.Contains(low, "must cover the cited primary location"), strings.Contains(low, "complete containing function"):
		fb.Code, fb.Field = citation.EEvidenceSpanIncomplete, "evidence_ids"
		fb.Expected = "evidence covering the complete handler span"
		if aids.RequiredSpan != "" {
			fb.Expected += " " + aids.RequiredSpan
		}
	case strings.Contains(low, "entry point does not match"):
		fb.Code, fb.Field, fb.Expected = citation.EHandlerMismatch, "entry_point", "exactly the route identity METHOD PATH"
		if aids.Route != "" {
			fb.Expected += " (" + aids.Route + ")"
		}
	case strings.Contains(low, "cannot carry unresolved questions"):
		fb.Code, fb.Field, fb.Expected = ESupportedWithQuestions, "unresolved_questions", "no open questions on a supported verdict (or submit unresolved)"
	case strings.Contains(low, "invalid_citation"):
		fb.Code, fb.Field, fb.Expected, fb.Repairable = EInvalidCitation, "candidate", "amend_candidate to a resolvable citation first, or submit unresolved", true
	case strings.Contains(low, "refutes"):
		fb.Code, fb.Field, fb.Expected, fb.Repairable = ESubmissionRejected, "verdict", "the cited source refutes this class; submit rejected or unresolved", true
	}
	return fb
}

// CandidateIdentity is the exported stable identity (feature 015 amendments).
func CandidateIdentity(f consolidate.Finding, repo string) string { return candidateIdentity(f, repo) }

// WriteManifest persists the manifest (after amendments).
func WriteManifest(resultsDir string, m *Manifest) error {
	return writeJSON(resultsDir+"/"+CandidateManifestFile, m)
}

// ApplyAmendment applies one amend_candidate request to the manifest (C-C7): the
// new citation must parse, resolve at the manifest revision and bind to a handler;
// the same resolved anchor keeps the identity, a different anchor creates a new
// candidate that supersedes the old one (no decision inherited). Returns the
// candidate the session should continue with and the recorded amendment.
func ApplyAmendment(m *Manifest, repo string, old *Candidate, path string, start, end int, reason, agent string, attempt int) (*Candidate, Amendment, *Feedback) {
	am := Amendment{CandidateID: old.ID, SessionAttempt: attempt, Original: old.Finding.Location, Reason: reason, Revision: m.Revision, Agent: agent, Outcome: "rejected"}
	text := fmt.Sprintf("%s:%d", path, start)
	if end > start {
		text = fmt.Sprintf("%s:%d-%d", path, start, end)
	}
	am.Amended = text
	c, perr := citation.Parse(text)
	if perr != nil {
		fb := FromCitationError(perr)
		am.Error = fb.Message
		return nil, am, &fb
	}
	if _, rerr := citation.Resolve(repo, m.Revision, &c); rerr != nil {
		fb := FromCitationError(rerr)
		am.Error = fb.Message
		return nil, am, &fb
	}
	b := citation.Bind(repo, c)
	if b.Handler == nil {
		fb := Feedback{Code: EAmendmentUnbound, Field: "path", Received: text, Expected: "a citation inside a handler function (the harness must resolve the enclosing function)", Repairable: true, Aids: citation.AidsFor(b)}
		am.Error = fb.Expected
		return nil, am, &fb
	}
	amended := old.Finding
	amended.Location = c.String()
	oldAnchor, _ := consolidate.AnchorOf(old.Finding, repo)
	newAnchor, _ := consolidate.AnchorOf(amended, repo)
	rec := CitationRecord{Original: text, Normalized: c.String(), Binding: &b, Status: CitationValid, Parsed: &c}
	am.Outcome = "accepted"
	if oldAnchor.File == newAnchor.File && oldAnchor.Function == newAnchor.Function && oldAnchor.Statement == newAnchor.Statement {
		old.Finding.Location = amended.Location
		old.Citation = &rec
		am.Identity = "kept"
		m.Amendments = append(m.Amendments, am)
		return old, am, nil
	}
	id := candidateIdentity(amended, repo)
	newID := "CAND-" + id[:24]
	for i := range m.Candidates {
		if m.Candidates[i].ID == newID { // already present (replay) — link and continue with it
			old.Superseded = newID
			am.Identity = "superseded_by:" + newID
			m.Amendments = append(m.Amendments, am)
			return &m.Candidates[i], am, nil
		}
	}
	nc := Candidate{ID: newID, Identity: id, Finding: amended, Citation: &rec, Supersedes: old.ID, LikelyGroup: old.LikelyGroup}
	nc.Finding.ID = newID
	old.Superseded = newID // before append: a reallocation would orphan the old pointer
	m.Candidates = append(m.Candidates, nc)
	m.Superseded = append(m.Superseded, SupersededPair{OldID: old.ID, NewID: newID})
	am.Identity = "superseded_by:" + newID
	m.Amendments = append(m.Amendments, am)
	return &m.Candidates[len(m.Candidates)-1], am, nil
}

// ReplayAmendments re-applies a prior manifest's ACCEPTED amendments to a freshly
// built manifest (resume). Same revision ⇒ idempotent replay; a different revision
// ⇒ every amendment is recorded as rejected with the mismatch (nothing applied).
func ReplayAmendments(m *Manifest, prior *Manifest, repo string) {
	if prior == nil || len(prior.Amendments) == 0 {
		return
	}
	for _, am := range prior.Amendments {
		if am.Outcome != "accepted" {
			continue
		}
		if prior.Revision != m.Revision {
			rej := am
			rej.Outcome, rej.Identity = "rejected", ""
			rej.Error = fmt.Sprintf("revision mismatch: amendment recorded at %s, manifest at %s", prior.Revision, m.Revision)
			m.Amendments = append(m.Amendments, rej)
			continue
		}
		var target *Candidate
		for i := range m.Candidates {
			if m.Candidates[i].ID == am.CandidateID {
				target = &m.Candidates[i]
			}
		}
		if target == nil {
			continue
		}
		c, perr := citation.Parse(am.Amended)
		if perr != nil {
			continue
		}
		ApplyAmendment(m, repo, target, c.Path, c.Start, c.End, am.Reason, am.Agent+" (replay)", am.SessionAttempt)
	}
}

// FailingSubmission is one rejected submission kept for diagnostics (C-C11): the
// COMPLETE arguments and the exact feedback — never truncated.
type FailingSubmission struct {
	CallSeq  int            `json:"call_seq"`
	Args     map[string]any `json:"args"`
	Feedback Feedback       `json:"feedback"`
	Code     string         `json:"code"`
}

// SourceRef is a source range a session captured (path + lines, no text).
type SourceRef struct {
	Path  string `json:"path"`
	Start int    `json:"start"`
	End   int    `json:"end"`
}
