package cli

import (
	"fmt"
	"io"
	"os"
	"strings"

	"crashscope/internal/classifier"
	"crashscope/internal/parser"
	"crashscope/internal/report"
	"crashscope/internal/version"
)

const usage = `Usage: crashscope [flags] <file>...

Offline analyzer for JVM fatal crash logs (hs_err_pid*.log).
Prints a verdict: probable cause and how to fix it.

Flags:
  --json     machine-readable JSON report
  --verbose  full details (all libraries, all events)
  --version  print version and exit
Exit codes: 0 cause identified, 1 unrecognized, 2 not an hs_err file, 3 usage error
`

// Run parses args and returns the process exit code.
func Run(args []string, stdout, stderr io.Writer) int {
	var files []string
	jsonOut, verbose := false, false
	for _, a := range args[1:] {
		switch a {
		case "--version":
			fmt.Fprintf(stdout, "crashscope %s\n", version.Version)
			return 0
		case "--json":
			jsonOut = true
		case "--verbose":
			verbose = true
		case "-h", "--help":
			fmt.Fprint(stdout, usage)
			return 0
		default:
			// Unknown flags must be a usage error (exit 3), not a
			// misleading "open --foo" file error (exit 2). "-" alone is
			// kept as a file path.
			if len(a) > 1 && strings.HasPrefix(a, "-") {
				fmt.Fprintf(stderr, "crashscope: unknown option %s\n\n%s", a, usage)
				return 3
			}
			files = append(files, a)
		}
	}
	if len(files) == 0 {
		fmt.Fprint(stderr, usage)
		return 3
	}

	exit := 0
	for _, path := range files {
		code := analyzeOne(path, jsonOut, verbose, stdout, stderr)
		if code > exit {
			exit = code
		}
	}
	return exit
}

func analyzeOne(path string, jsonOut, verbose bool, stdout, stderr io.Writer) int {
	raw, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintf(stderr, "crashscope: %v\n", err)
		return 2
	}
	r, err := parser.Parse(path, raw)
	if err != nil {
		fmt.Fprintf(stderr, "crashscope: %v\n", err)
		return 2
	}
	verdicts := classifier.Classify(r)
	if jsonOut {
		if err := report.RenderJSON(stdout, r, verdicts); err != nil {
			fmt.Fprintf(stderr, "crashscope: render: %v\n", err)
			return 2
		}
	} else {
		if err := report.RenderText(stdout, r, verdicts, verbose); err != nil {
			fmt.Fprintf(stderr, "crashscope: render: %v\n", err)
			return 2
		}
	}
	if verdicts[0].Confidence == "low" {
		return 1 // parsed fine, but unrecognized pattern
	}
	return 0
}
