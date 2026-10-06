package cli

import (
	"fmt"
	"io"

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
	if len(args) < 2 {
		fmt.Fprint(stderr, usage)
		return 3
	}
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
			files = append(files, a)
		}
	}
	_ = jsonOut
	_ = verbose
	if len(files) == 0 {
		fmt.Fprint(stderr, usage)
		return 3
	}
	fmt.Fprintln(stderr, "analysis not implemented yet")
	return 1
}
