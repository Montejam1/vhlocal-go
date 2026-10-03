// Command vhlocal is the single self-contained binary for the vhlocal
// vulnerability-assessment harness. Each current Python entry point becomes a
// subcommand: run, server, report, logs, sbom, bench, batch, and the
// maintenance/eval commands. See specs/002-golang-port/contracts/cli.md.
package main

import (
	"os"

	"vhlocal/internal/cli"
)

func main() {
	os.Exit(cli.Dispatch(os.Args[1:]))
}
