package cli

import (
	"flag"
	"fmt"
	"io/fs"
	"os"

	vhlocal "vhlocal"
	"vhlocal/internal/config"
	"vhlocal/internal/server"
)

func init() {
	register("server", "Run the HTTP engine + web UI", serverCmd)
}

type repeatable []string

func (r *repeatable) String() string { return fmt.Sprint(*r) }
func (r *repeatable) Set(v string) error {
	*r = append(*r, v)
	return nil
}

func serverCmd(args []string) int {
	fs2 := flag.NewFlagSet("server", flag.ContinueOnError)
	var (
		host       = fs2.String("host", config.DefaultServerBindHost, "Bind address")
		port       = fs2.Int("port", config.DefaultPort, "Listen port")
		skillDir   = fs2.String("skill-dir", "", "vulnhunt skill dir (default: embedded)")
		reportsDir = fs2.String("reports-dir", config.DefaultReportsDir(), "Where reports are written/indexed")
		ollamaHost = fs2.String("ollama-host", config.OllamaHost(), "Default inference endpoint")
		state      = fs2.String("state", config.StatePath(), "Job-queue persistence path")
		unsafeBind = fs2.Bool("unsafe-bind", false, "Required to bind a non-loopback address")
	)
	var allowRoots repeatable
	fs2.Var(&allowRoots, "allow-root", "Directory scans may target (repeatable)")
	fs2.SetOutput(os.Stderr)
	if err := fs2.Parse(normalizeLong(args)); err != nil {
		return ExitUsage
	}

	var webFS fs.FS
	if sub, err := fs.Sub(vhlocal.WebFS, "vhlocal/web"); err == nil {
		webFS = sub
	}

	srv, err := server.New(server.Config{
		Host: *host, Port: *port, SkillDir: *skillDir, ReportsDir: *reportsDir,
		OllamaHost: *ollamaHost, AllowRoots: allowRoots, StatePath: *state,
		UnsafeBind: *unsafeBind, Version: vhlocal.Version,
		WebFS: webFS, SkillFS: vhlocal.SkillFS,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "server: %v\n", err)
		return ExitUsage
	}
	fmt.Fprintf(os.Stderr, "vhlocal engine on http://%s:%d\n", *host, *port)
	if err := srv.Serve(); err != nil {
		fmt.Fprintf(os.Stderr, "server: %v\n", err)
		return ExitUsage
	}
	return ExitOK
}
