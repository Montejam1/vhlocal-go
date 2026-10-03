// Package guidance holds the reviewed remediation guidance table (feature 016, US2).
//
// It is reviewed data compiled into the binary, keyed by the weakness family keys of
// internal/knowledge. It is NOT generated from model output at report time, and no entry
// is produced by inference: a weakness with no entry takes the investigate branch rather
// than borrowing another family's advice (C-R4, C-R10, C-R11).
//
// Each entry answers one question: what change removes this mechanism? Where the fix
// depends on a policy or an invariant that a source-code scan cannot establish — who may
// act on an object, which rule must hold across two operations — the entry names the
// decision the application owner must make instead of inventing it (C-R7).
//
// Nothing here is an implemented or tested fix. Resolve attaches that disclosure to every
// recommendation it returns (C-R3).
package guidance

import "sort"

// WeaknessGuidance is the reviewed advice for one weakness family.
type WeaknessGuidance struct {
	// Family is the knowledge family key this entry serves.
	Family string
	// Mechanism states, in one clause, what is actually wrong.
	Mechanism string
	// Steps are the mechanism-specific changes, in the order they should be made.
	Steps []string
	// Checks are suggested ways to confirm the change. They are suggestions: nothing here
	// has been executed, and Resolve never presents them as having passed (C-R8).
	Checks []string
	// RequiresDecision names the policy or invariant the records cannot establish. Empty
	// where the mechanism fix needs no such decision.
	RequiresDecision string
	// FixSignals are substrings whose presence in a RECORDED recommendation shows that the
	// recommendation addresses this mechanism. They exist so a recorded fix that only
	// cleans input can be recognised as inapplicable to, say, a deserialization defect
	// without discarding it (FR-014, C-R9).
	FixSignals []string
}

// table is the reviewed guidance, one entry per knowledge family key.
var table = []WeaknessGuidance{
	{
		Family:     "code-injection",
		Mechanism:  "untrusted input reaches a dynamic code evaluator",
		Steps:      []string{"Remove the dynamic evaluation on this path: call the intended function directly, or dispatch through a lookup table keyed by a fixed set of operations you define.", "Where dynamic dispatch must remain, map the untrusted value through that fixed set and reject any value not in it."},
		Checks:     []string{"Confirm no path from request data reaches the evaluator in this file.", "Add a unit test that submits a hostile operation name and expects a rejection."},
		FixSignals: []string{"eval", "exec", "dynamic", "lookup table", "dispatch", "allow-list"},
	},
	{
		Family:     "template-injection",
		Mechanism:  "request data becomes part of the template source rather than template data",
		Steps:      []string{"Render from fixed template files only; never build template source out of request data.", "Pass untrusted values in as template variables so the engine treats them as data."},
		Checks:     []string{"Confirm every render call on this path names a template from a fixed set.", "Add a test that submits template syntax in the value and expects it to render literally."},
		FixSignals: []string{"template", "render", "variable", "autoescap"},
	},
	{
		Family:     "deserialization",
		Mechanism:  "untrusted bytes are deserialized by a format that can construct arbitrary objects",
		Steps:      []string{"Do not deserialize untrusted input with a format that can construct arbitrary objects; read the payload with a structured parser that returns plain data.", "Where objects must round-trip, restrict the permitted types to an explicit allow-list and reject anything else.", "If the payload comes from a trusted producer, authenticate it before parsing so the deserializer never sees unverified bytes."},
		Checks:     []string{"Confirm the loader used on this path cannot instantiate application or library classes.", "Add a test that feeds a crafted payload and expects a parse rejection rather than object construction."},
		FixSignals: []string{"deserializ", "unpickl", "pickle", "safe_load", "yaml.safe", "json", "allow-list of types", "signed"},
	},
	{
		Family:     "command-injection",
		Mechanism:  "untrusted input becomes part of a command line a shell re-parses",
		Steps:      []string{"Invoke the program with an argument list so no shell re-parses the arguments.", "Keep untrusted values out of the program name and out of any option that names something to execute."},
		Checks:     []string{"Confirm no shell is involved in this call path.", "Add a test that submits shell metacharacters and expects them to be treated as literal data."},
		FixSignals: []string{"argument list", "argv", "shell=false", "no shell", "subprocess", "quote"},
	},
	{
		Family:     "sql-injection",
		Mechanism:  "untrusted input is concatenated into a SQL statement",
		Steps:      []string{"Pass the untrusted value as a bound query parameter instead of concatenating it into the statement text.", "For identifiers that cannot be bound, choose them from a fixed set of column or table names."},
		Checks:     []string{"Confirm the statement text is constant for every input on this path.", "Add a test that submits a quote-and-comment payload and expects it to be stored or matched literally."},
		FixSignals: []string{"parameteriz", "bound parameter", "bind", "placeholder", "prepared statement", "orm"},
	},
	{
		Family:     "nosql-injection",
		Mechanism:  "request data is assembled into a query document, so it can carry query operators",
		Steps:      []string{"Build the query from typed values you extract field by field, not from a document assembled out of request data.", "Reject operator keys in any input used to build a query."},
		Checks:     []string{"Confirm the query document's shape is fixed on this path.", "Add a test that submits an operator key and expects it to be rejected."},
		FixSignals: []string{"typed", "operator key", "query document", "schema"},
	},
	{
		Family:     "xxe",
		Mechanism:  "the XML parser resolves external entities in untrusted documents",
		Steps:      []string{"Configure the parser to disable external entity resolution and DTD loading on this path.", "Parse untrusted XML with a parser whose entity resolution is off by default rather than toggling it per call."},
		Checks:     []string{"Confirm the parser options at this call site.", "Add a test that submits a document declaring an external entity and expects it to be ignored or rejected."},
		FixSignals: []string{"entity", "dtd", "resolve_entities", "defused", "parser option"},
	},
	{
		Family:     "path-traversal",
		Mechanism:  "a caller-supplied path component escapes the directory the code intends to serve",
		Steps:      []string{"Resolve the requested path against a fixed base directory and reject the result unless it is still inside that approved location.", "Compare the fully resolved real path, after symlink resolution, rather than the raw string."},
		Checks:     []string{"Add a test that requests a traversal sequence and expects a rejection.", "Confirm the base directory is a constant rather than a value derived from the request."},
		FixSignals: []string{"resolve", "realpath", "base director", "canonical", "within", "prefix", "approved"},
	},
	{
		Family:     "ssrf",
		Mechanism:  "the server makes a request to a destination the caller chooses",
		Steps:      []string{"Fetch only destinations whose host appears in a list you control, checked before the request is made.", "Resolve the host and refuse private, loopback and link-local addresses, re-checking after every redirect."},
		Checks:     []string{"Confirm the destination check happens before the outbound call on this path.", "Add a test that supplies an internal address and expects a refusal."},
		FixSignals: []string{"allow-list", "allowlist", "host", "redirect", "private address", "metadata"},
	},
	{
		Family:           "mass-assignment",
		Mechanism:        "request data is bound onto a model without restricting which fields a client may set",
		Steps:            []string{"Bind request data to an explicit field list rather than to the whole model.", "Ignore fields outside that list instead of merging whatever arrived."},
		Checks:           []string{"Confirm the bind names its fields explicitly on this path.", "Add a test that submits a field the client should not control and expects it to be ignored."},
		RequiresDecision: "which fields a client may set on this object; the records establish that the bind is unrestricted, not what the permitted set should be",
		FixSignals:       []string{"field list", "explicit field", "allow-list", "schema", "dto", "whitelist"},
	},
	{
		Family:     "xss",
		Mechanism:  "untrusted text reaches an HTML context without contextual escaping",
		Steps:      []string{"Render the value through the template engine's contextual escaping rather than inserting it into markup directly.", "Where HTML must be accepted, sanitize it server-side with a vetted allow-list library before storing it."},
		Checks:     []string{"Confirm the output context at this insertion point and that escaping matches it.", "Add a test that submits a script tag and expects escaped text in the response."},
		FixSignals: []string{"escap", "encode", "autoescap", "sanitiz", "template", "context"},
	},
	{
		Family:     "open-redirect",
		Mechanism:  "a caller-supplied value becomes the redirect destination",
		Steps:      []string{"Redirect only to paths inside the application, or to destinations from a list you control.", "Discard a destination supplied by the request when it names another host."},
		Checks:     []string{"Confirm the destination is validated before the redirect response is built.", "Add a test that supplies an external URL and expects it not to be used."},
		FixSignals: []string{"relative path", "allow-list", "allowlist", "host", "same site", "reject"},
	},
	{
		Family:           "privilege-escalation",
		Mechanism:        "an operation can be performed without holding the privilege it requires",
		Steps:            []string{"Derive the acting principal's privileges on the server from the authenticated session, never from a request field.", "Check the required privilege in the handler that performs the operation, before it takes effect."},
		Checks:           []string{"Confirm the privilege check cannot be bypassed by a different route to the same operation.", "Add a test that calls the operation as a lower-privileged principal and expects a refusal."},
		RequiresDecision: "which privilege each operation requires; the records establish that the check is absent, not what the policy should be",
		FixSignals:       []string{"privilege", "role", "session", "server-side", "check"},
	},
	{
		Family:           "missing-auth",
		Mechanism:        "the path is reachable without an authenticated principal",
		Steps:            []string{"Require an authenticated principal at the routing or middleware layer so a newly added handler cannot be left unprotected.", "Return the authentication failure before any side effect or data access occurs."},
		Checks:           []string{"Confirm the requirement is applied by default and this path is not excluded.", "Add a test that calls the path with no credentials and expects a refusal."},
		RequiresDecision: "which endpoints are intended to be public; the records establish that nothing authenticates this path, not whether that was intended",
		FixSignals:       []string{"authenticat", "middleware", "session", "login", "credential"},
	},
	{
		Family:           "access-control",
		Mechanism:        "the handler acts on an object without checking that the caller is permitted to",
		Steps:            []string{"Check the acting principal's permission for the specific object or operation inside the handler, before it reads or writes anything.", "Derive the principal from the authenticated session rather than from a parameter the caller controls.", "Fail closed: refuse the request when the permission cannot be established."},
		Checks:           []string{"Confirm every route reaching this object performs the same check.", "Add a test that requests another principal's object and expects a refusal."},
		RequiresDecision: "who may act on this object: the records establish that no check is performed, not what the authorization policy should be",
		FixSignals:       []string{"authoriz", "permission", "owner", "tenant", "principal", "session", "acl", "scope"},
	},
	{
		Family:     "weak-auth",
		Mechanism:  "credentials or sessions are handled in a way that makes them recoverable or reusable",
		Steps:      []string{"Store credentials with a memory-hard password hash and verify them with a constant-time comparison.", "Issue a new session identifier on login and invalidate it on logout."},
		Checks:     []string{"Confirm the stored format is the hash, not the credential.", "Add a test that the session identifier changes across a login."},
		FixSignals: []string{"hash", "argon", "bcrypt", "scrypt", "pbkdf2", "session", "constant-time", "rotate"},
	},
	{
		Family:     "weak-random",
		Mechanism:  "a security-relevant value comes from a predictable source",
		Steps:      []string{"Generate the value with the platform's cryptographically secure random source.", "Make it long enough that guessing is infeasible, and never derive it from a timestamp or a counter."},
		Checks:     []string{"Confirm the generator at this call site is the cryptographic one.", "Confirm the value's length and character space in the code that produces it."},
		FixSignals: []string{"secrets", "crypto/rand", "csprng", "secure random", "entropy", "token length"},
	},
	{
		Family:     "weak-crypto",
		Mechanism:  "a broken or misused cryptographic primitive protects the data",
		Steps:      []string{"Replace the primitive with a current, vetted one used through a high-level library interface.", "Derive keys with a key-derivation function and keep key material out of the source tree."},
		Checks:     []string{"Confirm the algorithm and mode at this call site against the library's current recommendation.", "Confirm no key or initialisation vector is a literal in the code."},
		FixSignals: []string{"aes", "gcm", "sha-256", "sha256", "kdf", "key derivation", "library", "primitive", "algorithm"},
	},
	{
		Family:     "hardcoded-secret",
		Mechanism:  "a credential is a literal in the source tree",
		Steps:      []string{"Remove the literal and read the value from configuration or a secret store at run time.", "Treat the committed value as disclosed: rotate it, and look through history for other copies."},
		Checks:     []string{"Confirm the literal is gone from the working tree and that the run-time lookup fails loudly when the value is absent.", "Confirm the rotation happened in the system that issues the credential."},
		FixSignals: []string{"environment", "secret store", "vault", "configuration", "rotate", "remove the literal"},
	},
	{
		Family:           "race-condition",
		Mechanism:        "a condition is checked and then acted on, with a window in between",
		Steps:            []string{"Perform the check and the dependent change atomically: one transaction at the appropriate isolation level, a conditional update, or a lock held across both.", "Re-evaluate the condition inside the atomic section rather than trusting the earlier read."},
		Checks:           []string{"Confirm both operations are inside the same atomic section on this path.", "Add a concurrent test that exercises both operations and asserts the invariant still holds."},
		RequiresDecision: "the invariant that must hold across the two operations; the records establish that the window exists, not which rule must not be violated",
		FixSignals:       []string{"atomic", "transaction", "lock", "select for update", "compare-and-set", "isolation"},
	},
	{
		Family:           "cors",
		Mechanism:        "the cross-origin policy grants more than the application needs",
		Steps:            []string{"Reflect only origins from a list you control, and never pair a wildcard origin with credentialed requests.", "State the permitted methods and headers explicitly instead of echoing the request's own."},
		Checks:           []string{"Confirm the response headers for a request from an unlisted origin.", "Confirm no code path echoes the request origin unchecked."},
		RequiresDecision: "which origins are trusted for this application; the records establish that the configuration is permissive, not what the policy should be",
		FixSignals:       []string{"origin", "allow-list", "allowlist", "credential", "wildcard", "header"},
	},
	{
		Family:           "rate-limiting",
		Mechanism:        "an expensive or sensitive operation can be repeated without limit",
		Steps:            []string{"Apply a limit per principal and per source for this operation, enforced before the expensive work begins.", "Return a retry signal rather than queueing unbounded work."},
		Checks:           []string{"Confirm the limit is enforced server-side on every route reaching this operation.", "Add a test that repeats the call past the limit and expects a retry signal."},
		RequiresDecision: "the acceptable request rate for this operation; the records establish that no limit exists, not what the limit should be",
		FixSignals:       []string{"rate limit", "throttle", "quota", "backoff", "retry-after", "lockout"},
	},
	{
		Family:     "resource-exhaustion",
		Mechanism:  "a single request can consume unbounded work or memory",
		Steps:      []string{"Bound what one request can cause: cap the input size, the result-set size and the iteration count before processing begins.", "Stream or paginate instead of materialising the whole input or result in memory."},
		Checks:     []string{"Confirm the cap is applied before allocation on this path.", "Add a test that submits an oversized input and expects a rejection rather than a slow success."},
		FixSignals: []string{"limit", "cap", "paginat", "stream", "timeout", "max size", "bound"},
	},
	{
		Family:     "timing",
		Mechanism:  "the duration of the operation reveals something about the secret it handles",
		Steps:      []string{"Compare secret values with a constant-time comparison function.", "Make the failure path do the same work as the success path so the duration does not reveal which branch ran."},
		Checks:     []string{"Confirm the comparison function at this call site is the constant-time one.", "Confirm both branches perform the same lookups."},
		FixSignals: []string{"constant-time", "compare_digest", "subtle.constanttime", "same work", "uniform"},
	},
	{
		Family:     "csrf",
		Mechanism:  "a state-changing request is accepted on the strength of the browser's ambient credentials",
		Steps:      []string{"Require a per-session anti-forgery token on every state-changing request and verify it on the server.", "Set the session cookie's same-site attribute so the browser does not attach it to cross-site requests."},
		Checks:     []string{"Confirm the token is verified for every state-changing route, not only this one.", "Add a test that omits the token and expects a refusal."},
		FixSignals: []string{"csrf", "anti-forgery", "token", "samesite", "same-site", "double submit"},
	},
	{
		Family:     "transport",
		Mechanism:  "the connection or its certificate is not verified",
		Steps:      []string{"Require TLS for this connection and verify the certificate chain and the hostname; do not disable verification.", "Refuse a plaintext fallback rather than retrying without TLS."},
		Checks:     []string{"Confirm verification is enabled at this call site and not switched off by configuration.", "Confirm the client fails when presented with an untrusted certificate."},
		FixSignals: []string{"tls", "https", "certificate", "verify", "hostname", "ca bundle"},
	},
	{
		Family:           "info-disclosure",
		Mechanism:        "the response or log carries information the caller should not receive",
		Steps:            []string{"Return a generic message to the caller and keep the diagnostic detail in server-side logs.", "Remove the sensitive fields from the response body and from anything else the client can read."},
		Checks:           []string{"Confirm the response for a failing request carries no internal detail.", "Confirm the log destination is not reachable by the caller."},
		RequiresDecision: "what counts as sensitive for this application; the records establish that the value is exposed, not whether its disclosure is acceptable",
		FixSignals:       []string{"generic message", "log", "redact", "remove the field", "mask", "internal detail"},
	},
}

// byFamily indexes the table for lookup.
var byFamily = func() map[string]WeaknessGuidance {
	m := make(map[string]WeaknessGuidance, len(table))
	for _, g := range table {
		m[g.Family] = g
	}
	return m
}()

// For returns the reviewed guidance for a weakness family key.
func For(family string) (WeaknessGuidance, bool) {
	g, ok := byFamily[family]
	return g, ok
}

// Families returns the family keys the table covers, sorted for deterministic output.
func Families() []string {
	out := make([]string, 0, len(table))
	for _, g := range table {
		out = append(out, g.Family)
	}
	sort.Strings(out)
	return out
}
