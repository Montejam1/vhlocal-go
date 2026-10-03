// Package cli implements subcommand dispatch for the vhlocal binary.
//
// Precedence for scan knobs (built-in default < profile < explicit flag) is
// realized per subcommand via flag.FlagSet with FlagSet.Visit (visits only the
// flags the user actually set), the Go analog of Python argparse.SUPPRESS.
package cli

import (
	"flag"
	"fmt"
	"os"
	"sort"
)

// Exit codes (parity with the Python entry points).
const (
	ExitOK    = 0
	ExitUsage = 2
)

// handler runs a subcommand given its argument slice (after the subcommand
// name) and returns a process exit code.
type handler func(args []string) int

// registry maps subcommand name -> (handler, one-line summary). Handlers are
// registered by each subcommand's file (run.go, server.go, ...). Unbuilt
// subcommands are registered as notImplemented so the surface is complete and
// discoverable while the port lands incrementally.
var registry = map[string]struct {
	run     handler
	summary string
}{}

func register(name, summary string, h handler) {
	registry[name] = struct {
		run     handler
		summary string
	}{run: h, summary: summary}
}

// Dispatch routes os.Args[1:] to a subcommand.
func Dispatch(args []string) int {
	if len(args) == 0 || args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		usage()
		if len(args) == 0 {
			return ExitUsage
		}
		return ExitOK
	}
	name := args[0]
	entry, ok := registry[name]
	if !ok {
		fmt.Fprintf(os.Stderr, "vhlocal: unknown subcommand %q\n\n", name)
		usage()
		return ExitUsage
	}
	return entry.run(args[1:])
}

func usage() {
	fmt.Fprintln(os.Stderr, "vhlocal — VulnHunter methodology against a local or paid model.")
	fmt.Fprintln(os.Stderr, "\nUsage: vhlocal <command> [flags]\n\nCommands:")
	names := make([]string, 0, len(registry))
	for n := range registry {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		fmt.Fprintf(os.Stderr, "  %-12s %s\n", n, registry[n].summary)
	}
	fmt.Fprintln(os.Stderr, "\nRun 'vhlocal <command> -h' for a command's flags.")
}

// parseInterspersed parses a FlagSet allowing flags and positionals in any order
// (argparse-style), returning the positional arguments. Go's flag package stops
// at the first non-flag; this loops to collect flags that follow positionals.
func parseInterspersed(fs *flag.FlagSet, args []string) ([]string, error) {
	args = normalizeLong(args)
	var positionals []string
	for {
		if err := fs.Parse(args); err != nil {
			return nil, err
		}
		rest := fs.Args()
		if len(rest) == 0 {
			break
		}
		positionals = append(positionals, rest[0])
		args = rest[1:]
	}
	return positionals, nil
}

// notImplemented is a placeholder handler for subcommands not yet ported.
func notImplemented(name string) handler {
	return func([]string) int {
		fmt.Fprintf(os.Stderr, "vhlocal %s: not yet implemented in the Go port\n", name)
		return ExitUsage
	}
}

func init() {
	// Register the full subcommand surface up front (contracts/cli.md). Ported
	// subcommands replace these placeholders in their own files' init().
	for _, s := range []struct{ name, summary string }{
		{"run", "Run a scan"},
		{"server", "Run the HTTP engine + web UI"},
		{"report", "Regenerate consolidated report(s); delete a report"},
		{"logs", "Read the central log (or one scan's slice)"},
		{"sbom", "Generate a CycloneDX SBOM for a repo"},
		{"bench", "Benchmark inference throughput"},
		{"batch", "Scan many repos from a CSV"},
		{"authz", "Authorization-map maintenance/eval"},
		{"membank", "Vulnerability-ledger maintenance"},
		{"policy-bench", "Policy benchmark"},
	} {
		if _, exists := registry[s.name]; !exists {
			register(s.name, s.summary, notImplemented(s.name))
		}
	}
}
