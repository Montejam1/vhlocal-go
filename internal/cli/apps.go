// Feature 014 (FR-028): `vhlocal applications` — list the registry and clean up
// demonstrably synthetic entries with a preview → confirm → backed-up apply flow.
package cli

import (
	"flag"
	"fmt"
	"os"

	"vhlocal/internal/apps"
	"vhlocal/internal/config"
)

func init() {
	register("applications", "List applications; cleanup synthetic registry entries", applicationsCmd)
}

func applicationsCmd(args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" {
		fmt.Fprintln(os.Stderr, "Usage: vhlocal applications list | cleanup --preview | cleanup --apply [--confirm <token>] [--reports-dir DIR] [--json]")
		return ExitUsage
	}
	switch args[0] {
	case "list":
		return applicationsList(args[1:])
	case "cleanup":
		return applicationsCleanup(args[1:])
	}
	fmt.Fprintf(os.Stderr, "applications: unknown subcommand %q\n", args[0])
	return ExitUsage
}

func applicationsList(args []string) int {
	fs := flag.NewFlagSet("applications list", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "Print JSON")
	reportsDir := fs.String("reports-dir", config.DefaultReportsDir(), "Reports directory")
	fs.SetOutput(os.Stderr)
	if _, err := parseInterspersed(fs, args); err != nil {
		return ExitUsage
	}
	list := apps.ListSummaries(*reportsDir)
	if *asJSON {
		printJSON(list)
		return ExitOK
	}
	for _, a := range list {
		fmt.Printf("%-40s %3d scan(s)  %s\n", a.Slug, a.Scans, a.Repo)
	}
	fmt.Printf("%d application(s)\n", len(list))
	return ExitOK
}

// applicationsCleanup: --preview prints the candidates and the token; --apply
// requires the token (from a preview) via --confirm, backs the registry up first
// and removes exactly the previewed ids. Neither flag → preview.
func applicationsCleanup(args []string) int {
	fs := flag.NewFlagSet("applications cleanup", flag.ContinueOnError)
	preview := fs.Bool("preview", false, "Show what would be removed (default)")
	apply := fs.Bool("apply", false, "Remove the previewed entries (requires --confirm <token>)")
	confirm := fs.String("confirm", "", "Preview token from a prior --preview run")
	asJSON := fs.Bool("json", false, "Print JSON")
	reportsDir := fs.String("reports-dir", config.DefaultReportsDir(), "Reports directory")
	fs.SetOutput(os.Stderr)
	if _, err := parseInterspersed(fs, args); err != nil {
		return ExitUsage
	}
	if !*apply || *preview {
		pv := apps.PreviewSynthetic(*reportsDir)
		if *asJSON {
			printJSON(pv)
			return ExitOK
		}
		for _, c := range pv.Candidates {
			fmt.Printf("would remove %-40s %s\n  reason: %s\n", c.Slug, c.Repo, c.Reason)
		}
		fmt.Printf("%d candidate(s); %d entr(y/ies) preserved\n", len(pv.Candidates), pv.PreservedCount)
		if pv.PreviewToken != "" {
			fmt.Printf("to apply: vhlocal applications cleanup --apply --confirm %s\n", pv.PreviewToken)
		}
		return ExitOK
	}
	res, err := apps.Apply(*reportsDir, *confirm)
	if err != nil {
		fmt.Fprintf(os.Stderr, "applications cleanup: %v (nothing changed)\n", err)
		return ExitUsage
	}
	if *asJSON {
		printJSON(res)
		return ExitOK
	}
	fmt.Printf("backup written: %s\n", res.BackupPath)
	for _, s := range res.Removed {
		fmt.Printf("removed %s\n", s)
	}
	fmt.Printf("%d entr(y/ies) removed\n", len(res.Removed))
	return ExitOK
}
