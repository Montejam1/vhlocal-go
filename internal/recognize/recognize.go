// Package recognize provides language-agnostic, static, offline recognition of
// investigation units (entry points and other security-relevant surfaces) across
// a multi-language baseline (feature 012). It NEVER executes or imports target
// code, requires no target-language toolchain/runtime, performs no network I/O,
// and builds with CGO disabled — Go recognition uses the standard library
// go/parser/go/ast; other languages use bounded, structure-aware lexers. Language
// support means concrete recognition of units/inputs/sensitive-operations, not a
// file-extension listing or a whole-repo generic fallback, and is never equated
// with enumerating HTTP routes.
package recognize

import "sort"

// Language is one of the supported baseline languages.
type Language string

const (
	LangPython     Language = "python"
	LangGo         Language = "go"
	LangJavaScript Language = "javascript"
	LangTypeScript Language = "typescript"
	LangJava       Language = "java"
	LangKotlin     Language = "kotlin"
	LangCSharp     Language = "csharp"
	LangC          Language = "c"
	LangCPP        Language = "cpp"
	LangRust       Language = "rust"
	LangRuby       Language = "ruby"
	LangPHP        Language = "php"
)

// AppType is an application type a unit belongs to (not HTTP-route-centric).
type AppType string

const (
	AppWeb      AppType = "web"
	AppCLI      AppType = "cli"
	AppLibrary  AppType = "library"
	AppParser   AppType = "parser"
	AppWorker   AppType = "worker"
	AppConsumer AppType = "consumer"
	AppRPC      AppType = "rpc"
	AppBrowser  AppType = "browser"
)

// SurfaceKind is the kind of recognized surface.
type SurfaceKind string

const (
	SurfaceWebRoute        SurfaceKind = "web-route"
	SurfaceCLICommand      SurfaceKind = "cli-command"
	SurfaceLibraryAPI      SurfaceKind = "library-api"
	SurfaceParserEntry     SurfaceKind = "parser-entry"
	SurfaceWorkerHandler   SurfaceKind = "worker-handler"
	SurfaceConsumerHandler SurfaceKind = "consumer-handler"
	SurfaceRPCMethod       SurfaceKind = "rpc-method"
	SurfaceBrowserSink     SurfaceKind = "browser-sink"
	SurfaceFallback        SurfaceKind = "fallback"
)

// Certainty is how fully a unit's attributes were statically resolved.
type Certainty string

const (
	Resolved   Certainty = "resolved"   // fully statically resolved
	Partial    Certainty = "partial"    // recognizable but some attr unresolved (dynamic expr)
	Unresolved Certainty = "unresolved" // recognizable registration, key attrs unknown
	// Ambiguous (feature 015, FR-030): a verb-named method on a receiver the file does
	// not resolve to a router, with a path-like first argument — disclosed, never in
	// the coverage denominator.
	Ambiguous Certainty = "ambiguous"
)

// Mechanism records how a recognizer works, for the support matrix + dependency
// budget (FR-039). Anything other than stdlib/lexer names a listed dependency.
type Mechanism string

const (
	MechStdlib Mechanism = "stdlib" // Go standard library (e.g. go/ast) — zero dependency
	MechLexer  Mechanism = "lexer"  // hand-written structure-aware lexer — zero dependency
)

// ExternalInput is a representative untrusted input attributed to a unit.
type ExternalInput struct {
	Kind     string `json:"kind"` // request-field|argv|env|message|file|stream|dom|other
	Name     string `json:"name"`
	Location string `json:"location"`
}

// SensitiveOp is a representative security-sensitive operation located in source.
type SensitiveOp struct {
	CWEClass  string `json:"cwe_class"`
	Operation string `json:"operation"`
	Location  string `json:"location"`
	Context   string `json:"context,omitempty"`
}

// Detection is one matched construct, for auditability.
type Detection struct {
	Construct string `json:"construct"`
	Location  string `json:"location"`
}

// InvestigationUnit is the central recognized element (supersedes the HTTP-only
// route). Ids are deterministic; see UnitID.
type InvestigationUnit struct {
	ID           string            `json:"id"`
	Language     Language          `json:"language"`
	Framework    string            `json:"framework,omitempty"`
	Module       string            `json:"module"`
	AppType      AppType           `json:"application_type"`
	SurfaceKind  SurfaceKind       `json:"surface_kind"`
	Location     string            `json:"location"` // file:line
	HandlerRef   string            `json:"handler_ref,omitempty"`
	SurfaceAttrs map[string]string `json:"surface_attrs,omitempty"` // e.g. web: method/path; cli: command
	Certainty    Certainty         `json:"certainty"`
	Inputs       []ExternalInput   `json:"inputs,omitempty"`
	SensitiveOps []SensitiveOp     `json:"sensitive_ops,omitempty"`
	Evidence     []Detection       `json:"evidence,omitempty"`
}

// Limitation is a visible recognition gap, kept rather than dropped.
type Limitation struct {
	Scope  string `json:"scope"` // file|module|language|construct
	Reason string `json:"reason"`
	Kind   string `json:"kind"` // unsupported|parse-error|dynamic-unresolved
}

// SourceFile is a first-party source file handed to a recognizer (already read;
// recognizers never open target files themselves — the caller confines reads).
type SourceFile struct {
	RelPath string // repo-relative
	Content []byte
}

// Module groups source files for one module/package.
type Module struct {
	Path  string // repo-relative module/package path
	Files []SourceFile
}

// Recognizer recognizes units for one language across its dedicated app types.
type Recognizer interface {
	Language() Language
	AppTypes() []AppType
	Mechanism() Mechanism
	// Recognize is pure static analysis over already-read files. It must be
	// deterministic and must not execute code, spawn processes, or do network I/O.
	Recognize(mod Module) ([]InvestigationUnit, []Limitation)
}

// registry holds the registered recognizers by language.
var registry = map[Language]Recognizer{}

// Register adds a recognizer (idempotent by language; last wins). Called from
// each lang_*.go init().
func Register(r Recognizer) { registry[r.Language()] = r }

// For returns the recognizer for a language, if registered.
func For(lang Language) (Recognizer, bool) { r, ok := registry[lang]; return r, ok }

// Registered returns the registered languages, sorted, for the support matrix.
func Registered() []Language {
	out := make([]Language, 0, len(registry))
	for l := range registry {
		out = append(out, l)
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}
