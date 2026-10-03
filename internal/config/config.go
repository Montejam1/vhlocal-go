// Package config resolves vhlocal's configuration inputs — environment
// variables and their defaults — with the same names and defaults as the Python
// implementation (spec FR-009). API keys are resolved from the environment or
// set in-memory at runtime and MUST NOT be persisted to disk, logs, or
// provenance (FR-009a).
package config

import (
	"os"
	"path/filepath"
)

// Defaults (parity with the Python tool).
const (
	DefaultModel          = "gpt-oss:120b"
	DefaultNumCtx         = 131072
	DefaultOllamaHost     = "http://localhost:11434"
	DefaultOpenAIHost     = "http://localhost:8080"
	OpenRouterHost        = "https://openrouter.ai/api" // fixed
	DefaultPort           = 8420
	DefaultServerBindHost = "127.0.0.1"
	DefaultMaxOutTokens   = 32768
)

// Environment variable names (parity — do not rename).
const (
	EnvOllamaHost    = "VHLOCAL_OLLAMA_HOST"
	EnvOpenAIHost    = "VHLOCAL_OPENAI_HOST"
	EnvOpenAIKey     = "VHLOCAL_OPENAI_API_KEY"
	EnvOpenRouterKey = "VHLOCAL_OPENROUTER_API_KEY"
	EnvLedgerDir     = "VHLOCAL_LEDGER_DIR"
	EnvProfilesDir   = "VHLOCAL_PROFILES_DIR"
	EnvLogFile       = "VHLOCAL_LOG_FILE"
	EnvLogDir        = "VHLOCAL_LOG_DIR"
	EnvActivityFile  = "VHLOCAL_ACTIVITY_FILE"
	EnvReviewsDir    = "VHLOCAL_REVIEWS_DIR"
	EnvViewsDir      = "VHLOCAL_VIEWS_DIR"
	EnvAssistDir     = "VHLOCAL_ASSIST_DIR"
)

// home returns the user's home directory, or "." if it cannot be determined.
func home() string {
	if h, err := os.UserHomeDir(); err == nil && h != "" {
		return h
	}
	return "."
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// OllamaHost is the default local inference endpoint ($VHLOCAL_OLLAMA_HOST or the
// localhost default).
func OllamaHost() string { return envOr(EnvOllamaHost, DefaultOllamaHost) }

// OpenAIHost is the default OpenAI-compatible endpoint.
func OpenAIHost() string { return envOr(EnvOpenAIHost, DefaultOpenAIHost) }

// DefaultReportsDir is ~/vulnhunter-reports.
func DefaultReportsDir() string { return filepath.Join(home(), "vulnhunter-reports") }

// LedgerDir is $VHLOCAL_LEDGER_DIR or ~/.vhlocal/ledger. The applications
// registry (applications.json) lives in its parent directory.
func LedgerDir() string {
	return envOr(EnvLedgerDir, filepath.Join(home(), ".vhlocal", "ledger"))
}

// ProfilesDir is $VHLOCAL_PROFILES_DIR or ~/.vhlocal/profiles.
func ProfilesDir() string {
	return envOr(EnvProfilesDir, filepath.Join(home(), ".vhlocal", "profiles"))
}

// LogFile resolves the central log path: $VHLOCAL_LOG_FILE, else
// $VHLOCAL_LOG_DIR/vhlocal.log, else ~/.vhlocal/vhlocal.log.
func LogFile() string {
	if v := os.Getenv(EnvLogFile); v != "" {
		return v
	}
	if d := os.Getenv(EnvLogDir); d != "" {
		return filepath.Join(d, "vhlocal.log")
	}
	return filepath.Join(home(), ".vhlocal", "vhlocal.log")
}

// ActivityFile is $VHLOCAL_ACTIVITY_FILE or ~/.vhlocal/activity.jsonl.
func ActivityFile() string {
	return envOr(EnvActivityFile, filepath.Join(home(), ".vhlocal", "activity.jsonl"))
}

// StatePath is the server job-queue store, ~/.vhlocal/jobs.json.
func StatePath() string {
	return filepath.Join(home(), ".vhlocal", "jobs.json")
}

// ReviewsDir is $VHLOCAL_REVIEWS_DIR or ~/.vhlocal/reviews — the durable human
// review-decision store (feature 010). It is additive and separate from scan
// evidence, which is never rewritten.
func ReviewsDir() string {
	return envOr(EnvReviewsDir, filepath.Join(home(), ".vhlocal", "reviews"))
}

// ViewsDir is $VHLOCAL_VIEWS_DIR or ~/.vhlocal/views — named saved queue
// filters/sort (feature 010).
func ViewsDir() string {
	return envOr(EnvViewsDir, filepath.Join(home(), ".vhlocal", "views"))
}

// AssistDir is $VHLOCAL_ASSIST_DIR or ~/.vhlocal/assist — persisted contextual-AI
// results, keyed by finding + action + revision (feature 010). Additive; holds no
// scan evidence.
func AssistDir() string {
	return envOr(EnvAssistDir, filepath.Join(home(), ".vhlocal", "assist"))
}

// OpenAIKeyFromEnv returns the OpenAI-compatible bearer key from the environment
// (may be empty). Never persisted.
func OpenAIKeyFromEnv() string { return os.Getenv(EnvOpenAIKey) }

// OpenRouterKeyFromEnv returns the OpenRouter key from the environment (may be
// empty). A runtime-set key (server /api/openrouter-key) is held separately in
// memory and takes precedence; neither is ever written to disk (FR-009a).
func OpenRouterKeyFromEnv() string { return os.Getenv(EnvOpenRouterKey) }
