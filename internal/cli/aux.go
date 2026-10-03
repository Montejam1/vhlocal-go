package cli

import (
	"context"
	"encoding/csv"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"encoding/json"

	vhlocal "vhlocal"
	"vhlocal/internal/client"
	"vhlocal/internal/config"
	"vhlocal/internal/engine"
	"vhlocal/internal/logsetup"
	"vhlocal/internal/membank"
	"vhlocal/internal/phases"
	"vhlocal/internal/sbom"
)

func selectPhasesOrAll(spec string) ([]string, error) { return phases.SelectPhases(spec) }

func printJSON(v any) {
	b, _ := json.MarshalIndent(v, "", "  ")
	fmt.Println(string(b))
}

func init() {
	register("report", "Regenerate consolidated report(s); delete a report", reportCmd)
	register("logs", "Read the central log (or one scan's slice)", logsCmd)
	register("sbom", "Generate a CycloneDX SBOM for a repo", sbomCmd)
	register("bench", "Score scan efficacy or benchmark inference throughput", benchDispatch)
	register("batch", "Scan many repos from a CSV", batchCmd)
	register("membank", "Vulnerability-ledger maintenance", membankCmd)
}

// --- report ---

func reportCmd(args []string) int {
	fs := flag.NewFlagSet("report", flag.ContinueOnError)
	all := fs.Bool("all", false, "Regenerate every report under --reports-dir")
	del := fs.Bool("delete", false, "Delete the given results directory instead")
	yes := fs.Bool("yes", false, "Skip the delete confirmation")
	reportsDir := fs.String("reports-dir", config.DefaultReportsDir(), "Reports directory")
	fs.SetOutput(os.Stderr)
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return ExitUsage
	}

	if *all {
		entries, err := os.ReadDir(*reportsDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "report: %v\n", err)
			return ExitUsage
		}
		n := 0
		for _, e := range entries {
			if !e.IsDir() {
				continue
			}
			dir := filepath.Join(*reportsDir, e.Name())
			if err := engine.Regenerate(dir); err == nil {
				n++
				fmt.Printf("regenerated %s\n", dir)
			}
		}
		fmt.Printf("regenerated %d report(s)\n", n)
		return ExitOK
	}

	if len(pos) < 1 {
		fmt.Fprintln(os.Stderr, "report: a <results-dir> is required (or --all)")
		return ExitUsage
	}
	dir, _ := filepath.Abs(pos[0])

	if *del {
		root, _ := filepath.Abs(*reportsDir)
		da, _ := filepath.Abs(dir)
		if !within(da, root) {
			fmt.Fprintf(os.Stderr, "report: refusing to delete outside the reports directory (%s)\n", root)
			return ExitUsage
		}
		if !*yes {
			fmt.Fprintf(os.Stderr, "Delete %s ? Re-run with --yes to confirm.\n", dir)
			return ExitUsage
		}
		if err := os.RemoveAll(dir); err != nil {
			fmt.Fprintf(os.Stderr, "report: delete failed: %v\n", err)
			return ExitUsage
		}
		fmt.Printf("deleted %s\n", dir)
		return ExitOK
	}

	if err := engine.Regenerate(dir); err != nil {
		fmt.Fprintf(os.Stderr, "report: %v\n", err)
		return ExitUsage
	}
	fmt.Printf("regenerated %s\n", filepath.Join(dir, "SCAN_REPORT.md"))
	return ExitOK
}

func within(target, root string) bool {
	if target == root {
		return true
	}
	rel, err := filepath.Rel(root, target)
	return err == nil && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator))
}

// --- logs ---

func logsCmd(args []string) int {
	fs := flag.NewFlagSet("logs", flag.ContinueOnError)
	tail := fs.Int("tail", 0, "Show only the last N lines (0 = all)")
	level := fs.String("level", "", "Minimum level: DEBUG|INFO|WARNING|ERROR|CRITICAL")
	logFile := fs.String("log-file", config.LogFile(), "Central log path")
	fs.SetOutput(os.Stderr)
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return ExitUsage
	}
	scanTag := ""
	if len(pos) >= 1 {
		scanTag = pos[0]
	}
	text, err := logsetup.ReadLog(*logFile, *tail, scanTag, logsetup.ParseLevel(*level))
	if err != nil {
		fmt.Fprintf(os.Stderr, "logs: %v\n", err)
		return ExitUsage
	}
	if text != "" {
		fmt.Println(text)
	}
	return ExitOK
}

// --- sbom ---

func sbomCmd(args []string) int {
	fs := flag.NewFlagSet("sbom", flag.ContinueOnError)
	out := fs.String("out", "sbom.cdx.json", "Output path")
	fs.SetOutput(os.Stderr)
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return ExitUsage
	}
	if len(pos) < 1 {
		fmt.Fprintln(os.Stderr, "sbom: a <repo> is required")
		return ExitUsage
	}
	repo, _ := filepath.Abs(pos[0])
	if err := sbom.WriteTo(repo, *out, time.Now().UTC().Format(time.RFC3339)); err != nil {
		fmt.Fprintf(os.Stderr, "sbom: %v\n", err)
		return ExitUsage
	}
	sum := sbom.Summarize(repo)
	fmt.Printf("wrote %s (%d components across %d ecosystems)\n", *out, sum.Total, len(sum.ByEcosystem))
	return ExitOK
}

// --- bench ---

func benchCmd(args []string) int {
	fs := flag.NewFlagSet("bench", flag.ContinueOnError)
	backend := fs.String("backend", "ollama", "Inference backend")
	host := fs.String("host", "", "Endpoint")
	model := fs.String("model", config.DefaultModel, "Model")
	fs.SetOutput(os.Stderr)
	if _, err := parseInterspersed(fs, args); err != nil {
		return ExitUsage
	}
	resolvedHost := *host
	if resolvedHost == "" {
		if *backend == "openai" {
			resolvedHost = config.OpenAIHost()
		} else {
			resolvedHost = config.OllamaHost()
		}
	}
	prov, err := buildProvider(*backend, resolvedHost)
	if err != nil {
		fmt.Fprintf(os.Stderr, "bench: %v\n", err)
		return ExitUsage
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	start := time.Now()
	resp, err := prov.Chat(ctx, client.ChatRequest{
		Model: *model, NumCtx: 4096,
		Messages: []client.Message{{Role: "user", Content: "Reply with a single short paragraph about secure coding."}},
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "bench: %v\n", err)
		return ExitUsage
	}
	secs := time.Since(start).Seconds()
	tps := 0.0
	if secs > 0 {
		tps = float64(resp.Usage.CompletionTokens) / secs
	}
	fmt.Printf("model=%s backend=%s host=%s\n", *model, *backend, resolvedHost)
	fmt.Printf("prompt=%d completion=%d tokens | %.2fs | %.1f tok/s\n",
		resp.Usage.PromptTokens, resp.Usage.CompletionTokens, secs, tps)
	return ExitOK
}

// --- batch ---

func batchCmd(args []string) int {
	fs := flag.NewFlagSet("batch", flag.ContinueOnError)
	skillDir := fs.String("skill-dir", "", "vulnhunt skill dir")
	model := fs.String("model", config.DefaultModel, "Model")
	host := fs.String("host", "", "Endpoint")
	backend := fs.String("backend", "ollama", "Backend")
	reportsDir := fs.String("reports-dir", config.DefaultReportsDir(), "Reports dir")
	phasesFlag := fs.String("phases", "all", "Phase subset")
	fs.SetOutput(os.Stderr)
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return ExitUsage
	}
	if len(pos) < 1 {
		fmt.Fprintln(os.Stderr, "batch: a <csv> of repo[,app_id] rows is required")
		return ExitUsage
	}
	f, err := os.Open(pos[0])
	if err != nil {
		fmt.Fprintf(os.Stderr, "batch: %v\n", err)
		return ExitUsage
	}
	defer f.Close()
	rows, err := csv.NewReader(f).ReadAll()
	if err != nil {
		fmt.Fprintf(os.Stderr, "batch: %v\n", err)
		return ExitUsage
	}
	resolvedHost := *host
	if resolvedHost == "" {
		resolvedHost = config.OllamaHost()
	}
	prov, err := buildProvider(*backend, resolvedHost)
	if err != nil {
		fmt.Fprintf(os.Stderr, "batch: %v\n", err)
		return ExitUsage
	}
	skill := resolveSkill(*skillDir)
	ok := 0
	for _, row := range rows {
		if len(row) == 0 || strings.TrimSpace(row[0]) == "" || strings.HasPrefix(row[0], "#") {
			continue
		}
		repo, _ := filepath.Abs(strings.TrimSpace(row[0]))
		phaseList, perr := selectPhasesOrAll(*phasesFlag)
		if perr != nil {
			fmt.Fprintf(os.Stderr, "batch: %v\n", perr)
			return ExitUsage
		}
		stamp := time.Now().Format("2006-01-02-150405")
		resultsDir := filepath.Join(*reportsDir,
			fmt.Sprintf("%s_VULNHUNT_RESULTS_%s_%s", filepath.Base(repo), modelTag(*model), stamp))
		spec := engine.ScanSpec{
			Repo: repo, ResultsDir: resultsDir, SkillDir: skillDirPath(*skillDir),
			Model: *model, Host: resolvedHost, Backend: *backend, NumCtx: config.DefaultNumCtx,
			Phases: phaseList, MaxPartitions: 8, MaxOutputTokens: config.DefaultMaxOutTokens,
			QualityStrictness: "balanced", IaCLens: true, EngineVersion: vhlocal.Version, ScanTag: stamp,
		}
		fmt.Printf("scanning %s → %s\n", repo, resultsDir)
		if _, err := engine.Execute(context.Background(), spec, engine.Providers{Hunt: prov}, skill, nil); err != nil {
			fmt.Fprintf(os.Stderr, "  batch row failed: %v\n", err)
			continue
		}
		ok++
	}
	fmt.Printf("batch complete: %d/%d repos scanned\n", ok, len(rows))
	return ExitOK
}

// --- membank ---

func membankCmd(args []string) int {
	fs := flag.NewFlagSet("membank", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)
	pos, err := parseInterspersed(fs, args)
	if err != nil {
		return ExitUsage
	}
	sub := "list"
	if len(pos) >= 1 {
		sub = pos[0]
	}
	switch sub {
	case "list":
		sums, err := membank.List()
		if err != nil {
			fmt.Fprintf(os.Stderr, "membank: %v\n", err)
			return ExitUsage
		}
		if len(sums) == 0 {
			fmt.Println("no ledgers")
			return ExitOK
		}
		for _, s := range sums {
			fmt.Printf("%-28s runs=%d total=%d reliable=%d  %s\n", s.Slug, s.RunsRecorded, s.Total, s.Reliable, s.TargetName)
		}
		return ExitOK
	case "show":
		if len(pos) < 2 {
			fmt.Fprintln(os.Stderr, "membank show <slug>")
			return ExitUsage
		}
		d, ok := membank.LoadDetail(pos[1])
		if !ok {
			fmt.Fprintln(os.Stderr, "no such ledger")
			return ExitUsage
		}
		printJSON(d)
		return ExitOK
	default:
		fmt.Fprintf(os.Stderr, "membank: unknown subcommand %q (list|show)\n", sub)
		return ExitUsage
	}
}
