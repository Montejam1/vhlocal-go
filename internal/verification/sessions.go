package verification

import (
	"bufio"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// SessionsFile records per-candidate verification session outcomes so a missing
// decision can be explained (feature 007, FR-023): why did the session not submit?
const SessionsFile = "verification_sessions.json"

// CallsFile is the per-call/attempt record (feature 015, FR-026, C-C10): one JSON
// line per tool call with its own class/code/message — never only the session's last.
const CallsFile = "verification_calls.jsonl"

// Failure classes (feature 014, FR-018): per-operation diagnosis so a failed
// session names WHAT failed, not just that it did. Keys of FailuresByClass.
const (
	FailTransport         = "transport"           // provider transport error (generic kind)
	FailToolEnvelope      = "tool_envelope"       // provider tool-call parse error (KindToolParse)
	FailInvalidToolArgs   = "invalid_tool_args"   // Read/Grep/capture_evidence argument errors
	FailInvalidSubmission = "invalid_submission"  // rejected evidence/decision submission
	FailTurnExhaustion    = "turn_exhaustion"     // max_turns reached
	FailRepeated          = "repeated_submission" // identical rejected submission repeated (feature 015)
)

// Provenance is the effective provider identity observed on a session's calls.
type Provenance struct {
	Backend        string `json:"backend"`
	Endpoint       string `json:"endpoint"`
	RequestedModel string `json:"requested_model"`
	ReturnedModel  string `json:"returned_model"`
}

// SessionOutcome is one candidate's verification session accounting.
type SessionOutcome struct {
	CandidateID string `json:"candidate_id"`
	StopReason  string `json:"stop_reason"` // complete | tool_repair | max_turns | endpoint_failure | repeated_submission | cancelled
	Turns       int    `json:"turns"`
	Failures    int    `json:"failures"` // recoverable tool/validation failures (all classes)

	// Feature 014 (FR-018) — additive per-operation diagnosis.
	FailuresByClass       map[string]int `json:"failures_by_class,omitempty"`
	LastOperation         string         `json:"last_operation,omitempty"`
	LastContractViolation string         `json:"last_contract_violation,omitempty"`

	// Feature 015 (FR-026/027) — call count, effective model/provenance, explicit
	// `unresolved` (a decision, not a failure), amendment, stop code.
	Calls              int         `json:"calls,omitempty"`
	Model              string      `json:"model,omitempty"`
	Provenance         *Provenance `json:"provenance,omitempty"`
	ExplicitUnresolved bool        `json:"explicit_unresolved,omitempty"`
	Amended            bool        `json:"amended,omitempty"`
	StopCode           string      `json:"stop_code,omitempty"`
}

// CallRecord is one line of verification_calls.jsonl.
type CallRecord struct {
	CandidateID    string         `json:"candidate_id"`
	SessionAttempt int            `json:"session_attempt"`
	CallSeq        int            `json:"call_seq"`
	TS             string         `json:"ts"`
	Operation      string         `json:"operation"`
	Args           map[string]any `json:"args,omitempty"` // diagnostic subset (never source text)
	ArgsDigest     string         `json:"args_digest,omitempty"`
	Outcome        string         `json:"outcome"` // ok | error
	Class          string         `json:"class,omitempty"`
	Code           string         `json:"code,omitempty"`
	Message        string         `json:"message,omitempty"`
	Feedback       string         `json:"feedback,omitempty"`
	RepairedByCall int            `json:"repaired_by_call,omitempty"`
	Model          string         `json:"model,omitempty"`
}

// DominantClass returns the failure class with the highest count ("" when none),
// ties broken by a fixed order so reasons are deterministic.
func (s SessionOutcome) DominantClass() string {
	order := []string{FailTransport, FailToolEnvelope, FailInvalidSubmission, FailRepeated, FailInvalidToolArgs, FailTurnExhaustion}
	best, bestN := "", 0
	for _, k := range order {
		if n := s.FailuresByClass[k]; n > bestN {
			best, bestN = k, n
		}
	}
	return best
}

// WriteSessions persists the per-candidate session outcomes.
func WriteSessions(resultsDir string, outcomes []SessionOutcome) error {
	if outcomes == nil {
		outcomes = []SessionOutcome{}
	}
	return writeJSON(filepath.Join(resultsDir, SessionsFile), outcomes)
}

// LoadSessions reads the persisted session outcomes as a map by candidate id.
func LoadSessions(resultsDir string) map[string]SessionOutcome {
	out := map[string]SessionOutcome{}
	b, err := os.ReadFile(filepath.Join(resultsDir, SessionsFile))
	if err != nil {
		return out
	}
	var list []SessionOutcome
	if json.Unmarshal(b, &list) != nil {
		return out
	}
	for _, s := range list {
		out[s.CandidateID] = s
	}
	return out
}

// AppendCalls appends call records (one JSON line each) to verification_calls.jsonl.
func AppendCalls(resultsDir string, calls []CallRecord) error {
	if len(calls) == 0 {
		return nil
	}
	f, err := os.OpenFile(filepath.Join(resultsDir, CallsFile), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	w := bufio.NewWriter(f)
	for _, c := range calls {
		b, err := json.Marshal(c)
		if err != nil {
			return err
		}
		w.Write(b)
		w.WriteByte('\n')
	}
	return w.Flush()
}

// LoadCalls reads verification_calls.jsonl (nil when absent).
func LoadCalls(resultsDir string) []CallRecord {
	f, err := os.Open(filepath.Join(resultsDir, CallsFile))
	if err != nil {
		return nil
	}
	defer f.Close()
	var out []CallRecord
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 16*1024*1024)
	for sc.Scan() {
		var c CallRecord
		if json.Unmarshal(sc.Bytes(), &c) == nil {
			out = append(out, c)
		}
	}
	return out
}

// Aggregates summarizes sessions for verification_metrics.json (C-C10):
// occurrences (every failure) vs sessions (with ≥1 failure of the class) vs stop
// reasons, with an explicit overlap note — a session can appear under several
// classes, so the three views never sum to each other.
func Aggregates(sessions []SessionOutcome) map[string]any {
	occ, sess, stops := map[string]int{}, map[string]int{}, map[string]int{}
	explicit, amended, calls := 0, 0, 0
	for _, s := range sessions {
		for class, n := range s.FailuresByClass {
			occ[class] += n
			sess[class]++
		}
		if s.StopReason != "" {
			stops[s.StopReason]++
		}
		if s.ExplicitUnresolved {
			explicit++
		}
		if s.Amended {
			amended++
		}
		calls += s.Calls
	}
	return map[string]any{
		"sessions":             len(sessions),
		"calls":                calls,
		"occurrences_by_class": occ,
		"sessions_by_class":    sess,
		"stop_reasons":         stops,
		"explicit_unresolved":  explicit,
		"amended_sessions":     amended,
		"overlap_note": "occurrences count every failure; sessions_by_class counts sessions with at least one failure of that class; " +
			"a session can appear under several classes and ends with exactly one stop reason, so these views do not sum to each other",
	}
}

// EnrichReasons rewrites the generic "no decision supplied" reason for candidates
// whose session ended without submitting, naming the cause and attempt/failure
// counts so the outcome is actionable (FR-023). Other reasons are left untouched.
func EnrichReasons(rec *Reconciliation, sessions map[string]SessionOutcome) {
	if rec == nil {
		return
	}
	for i := range rec.Results {
		r := &rec.Results[i]
		if r.Record != nil || r.Status != "unresolved" || r.Reason != "No verification decision supplied" {
			continue
		}
		if s, ok := sessions[r.CandidateID]; ok {
			r.Reason = fmt.Sprintf(
				"no decision submitted — session ended: %s after %d turn(s), %d recoverable tool failure(s)",
				s.StopReason, s.Turns, s.Failures)
			// Feature 014 (FR-018): name the dominant failure class and the violated
			// contract so the outcome is diagnosable per operation.
			if dc := s.DominantClass(); dc != "" {
				r.Reason += fmt.Sprintf("; dominant failure: %s", dc)
				if s.LastOperation != "" {
					r.Reason += fmt.Sprintf(" at %s", s.LastOperation)
				}
				if s.LastContractViolation != "" {
					r.Reason += fmt.Sprintf(" — %s", s.LastContractViolation)
				}
			}
		}
	}
}

// classOrder yields the classes in a deterministic order for rendering.
func classOrder(m map[string]int) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

var _ = classOrder
var _ = strings.TrimSpace
