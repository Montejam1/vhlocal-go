package cli

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"vhlocal/internal/engine"
)

type variantsFlag []string

func (v *variantsFlag) String() string     { return strings.Join(*v, ";") }
func (v *variantsFlag) Set(s string) error { *v = append(*v, s); return nil }
func init() {
	register("verify-compare", "Compare explicitly configured verifiers on a frozen manifest", compareCmd)
}
func compareCmd(args []string) int {
	fs := flag.NewFlagSet("verify-compare", flag.ContinueOnError)
	manifest := fs.String("manifest", "", "Frozen candidate_manifest.json")
	repo := fs.String("repo", "", "Read-only source checkout")
	revision := fs.String("revision", "", "Manifest revision; clean git commit or tree-sha256 fingerprint")
	out := fs.String("out", "", "New comparison output directory outside target")
	truth := fs.String("truth", "", "Optional ground truth (never sent to the provider)")
	model := fs.String("model", "", "Base model for prompt-only variants")
	backend := fs.String("backend", "", "Explicit provider backend")
	host := fs.String("host", "", "Explicit provider endpoint")
	dry := fs.Bool("dry-run", false, "Record variants as not run; make no provider calls")
	ctxSize := fs.Int("num-ctx", 32768, "Verifier context window")
	maxOut := fs.Int("max-output-tokens", 0, "Verifier output limit")
	var variants variantsFlag
	fs.Var(&variants, "variant", "Repeat: model=NAME,backend=BACKEND,host=URL or prompt=FILE (with base options)")
	if fs.Parse(args) != nil || *manifest == "" || *repo == "" || *revision == "" || *out == "" || len(variants) == 0 || fs.NArg() != 0 {
		return ExitUsage
	}
	if *ctxSize < 1 || *maxOut < 0 {
		fmt.Fprintln(os.Stderr, "context must be positive and output limit nonnegative")
		return ExitUsage
	}
	sp := engine.ComparisonSpec{Manifest: *manifest, Repo: *repo, Revision: *revision, OutputDir: *out, Truth: *truth, NumCtx: *ctxSize, MaxOutputTokens: *maxOut}
	defaultPrompt, err := resolveSkill("").Prompt("phase2b_session.md")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return ExitUsage
	}
	for i, raw := range variants {
		m, b, h, prompt := *model, *backend, *host, defaultPrompt
		for _, kv := range strings.Split(raw, ",") {
			k, v, ok := strings.Cut(kv, "=")
			if !ok || v == "" {
				return ExitUsage
			}
			switch k {
			case "model":
				m = v
			case "backend":
				b = v
			case "host":
				h = v
			case "prompt":
				data, e := os.ReadFile(v)
				if e != nil {
					fmt.Fprintln(os.Stderr, e)
					return ExitUsage
				}
				prompt = string(data)
			default:
				return ExitUsage
			}
		}
		if m == "" || b == "" || (h == "" && b != "openrouter") {
			fmt.Fprintln(os.Stderr, "each variant requires an explicit model, backend and endpoint (OpenRouter has a fixed endpoint)")
			return ExitUsage
		}
		if b != "ollama" && b != "openai" && b != "openrouter" {
			fmt.Fprintln(os.Stderr, "unsupported backend:", b)
			return ExitUsage
		}
		v := engine.CompareVariant{Name: fmt.Sprintf("variant-%02d", i+1), Model: m, Prompt: prompt, Backend: b, Endpoint: h}
		if !*dry {
			v.Provider, err = buildProvider(b, h)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
				return ExitUsage
			}
		}
		sp.Variants = append(sp.Variants, v)
	}
	result, err := engine.CompareVerification(context.Background(), sp)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return ExitUsage
	}
	printJSON(result)
	return ExitOK
}
