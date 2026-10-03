package cli

import (
	"flag"
	"fmt"
	"os"
	"vhlocal/internal/benchmark"
)

func benchDispatch(args []string) int {
	if len(args) > 0 && args[0] == "efficacy" {
		return benchEfficacy(args[1:])
	}
	if len(args) > 0 && args[0] == "throughput" {
		args = args[1:]
	}
	return benchCmd(args)
}

func benchEfficacy(args []string) int {
	fs := flag.NewFlagSet("bench efficacy", flag.ContinueOnError)
	results := fs.String("results", "", "Existing results directory (no scan is launched)")
	truthPath := fs.String("truth", "", "Ground-truth file outside the scanned target")
	basePath := fs.String("baseline", "", "Optional frozen baseline")
	jsonOut := fs.Bool("json", false, "JSON output")
	if fs.Parse(args) != nil || *results == "" || *truthPath == "" || fs.NArg() != 0 {
		fmt.Fprintln(os.Stderr, "bench efficacy requires --results and --truth")
		return ExitUsage
	}
	truth, err := benchmark.LoadTruth(*truthPath)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return ExitUsage
	}
	scored, err := benchmark.Score(*results, truth)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return ExitUsage
	}
	diff := []string{}
	regressions := []benchmark.Regression{}
	if *basePath != "" {
		base, e := benchmark.LoadBaseline(*basePath)
		if e != nil {
			fmt.Fprintln(os.Stderr, e)
			return ExitUsage
		}
		diff = benchmark.ConfigDiff(scored.Config, base.Config)
		regressions = benchmark.Compare(scored, base, benchmark.Policy{Version: base.PolicyVersion, Tolerance: base.Tolerance})
	}
	if *jsonOut {
		printJSON(struct {
			ConfigDiff  []string               `json:"config_diff"`
			Results     benchmark.Results      `json:"results"`
			Regressions []benchmark.Regression `json:"regressions"`
		}{diff, scored, regressions})
	} else {
		fmt.Printf("Configuration differences: %v\nSupported: %d TP / %d FP / %d FN; precision %.3f, recall %.3f\nSafe-control false positives: %d\nProvider: %s; live: %t; cost USD: %v\n", diff, scored.Supported.TP, scored.Supported.FP, scored.Supported.FN, scored.Supported.Precision, scored.Supported.Recall, len(scored.SafeControlFP), scored.Provider, scored.Live, scored.Cost.USD)
		for _, r := range regressions {
			fmt.Printf("Regression: %+v\n", r)
		}
	}
	if len(regressions) > 0 {
		return 1
	}
	return ExitOK
}
