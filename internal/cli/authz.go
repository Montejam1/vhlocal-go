package cli

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"

	"vhlocal/internal/authz"
	"vhlocal/internal/config"
	"vhlocal/internal/reports"
)

func init() {
	register("authz", "Authorization-map maintenance/eval", authzCmd)
	register("policy-bench", "Policy benchmark (reduced port)", policyBenchCmd)
}

// authzCmd builds/prints a repo's authorization map (endpoints + auth gaps).
func authzCmd(args []string) int {
	fs := flag.NewFlagSet("authz", flag.ContinueOnError)
	out := fs.String("out", "", "Write authz_map.json here (default: stdout)")
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(normalizeLong(args)); err != nil {
		return ExitUsage
	}
	if fs.NArg() < 1 {
		fmt.Fprintln(os.Stderr, "authz: a <repo> is required")
		return ExitUsage
	}
	repo, _ := filepath.Abs(fs.Arg(0))
	m := authz.Build(repo)
	if *out != "" {
		if _, err := authz.Write(repo, filepath.Dir(*out)); err != nil {
			fmt.Fprintf(os.Stderr, "authz: %v\n", err)
			return ExitUsage
		}
		fmt.Printf("wrote %s\n", filepath.Join(filepath.Dir(*out), authz.File))
	} else {
		printJSON(m)
	}
	fmt.Fprintf(os.Stderr, "%d endpoints, %d protected, %d auth gaps\n", m.Total, m.Protected, len(m.Gaps))
	return ExitOK
}

// policyBenchCmd is a reduced port: it reports how many findings across the
// reports directory cleared the statically-supported bar vs. remained
// hypotheses — a coarse precision signal. Full policy benchmarking is not ported.
func policyBenchCmd(args []string) int {
	fs := flag.NewFlagSet("policy-bench", flag.ContinueOnError)
	reportsDir := fs.String("reports-dir", config.DefaultReportsDir(), "Reports directory")
	fs.SetOutput(os.Stderr)
	if err := fs.Parse(normalizeLong(args)); err != nil {
		return ExitUsage
	}
	rs, err := reports.Index(*reportsDir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "policy-bench: %v\n", err)
		return ExitUsage
	}
	totalFindings, totalHyp := 0, 0
	for _, r := range rs {
		totalFindings += r.Findings
		totalHyp += r.Hypotheses
	}
	fmt.Printf("reports=%d  findings=%d  hypotheses=%d\n", len(rs), totalFindings, totalHyp)
	fmt.Fprintln(os.Stderr, "note: reduced port — full policy benchmarking is not yet implemented")
	return ExitOK
}
