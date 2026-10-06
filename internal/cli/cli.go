package cli

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
	"syscall"

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
	var renderErr error
	if jsonOut {
		renderErr = report.RenderJSON(stdout, r, verdicts)
	} else {
		renderErr = report.RenderText(stdout, r, verdicts, verbose)
	}
	if renderErr != nil {
		if isBrokenPipe(renderErr) {
			// The reader closed stdout early (e.g. `crashscope f | head`).
			// The file parsed fine — this must not look like exit 2.
			return 0
		}
		// A genuine delivery failure is neither a file problem (2) nor a
		// usage error (3): the verdict exists but could not be printed.
		fmt.Fprintf(stderr, "crashscope: render: %v\n", renderErr)
		return 1
	}
	if verdicts[0].Confidence == "low" {
		return 1 // parsed fine, but unrecognized pattern
	}
	return 0
}

// isBrokenPipe reports whether err is a closed-reader pipe on stdout, e.g.
// `crashscope file | head`. On Unix the Go runtime turns fd-1 EPIPE into a
// process-killing SIGPIPE before this code runs, so in practice this
// surfaces on Windows ("pipe is being closed" / "pipe has been ended") and
// from injected writers in tests.
func isBrokenPipe(err error) bool {
	if errors.Is(err, syscall.EPIPE) || errors.Is(err, os.ErrClosed) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "broken pipe") ||
		strings.Contains(msg, "pipe is being closed") ||
		strings.Contains(msg, "pipe has been ended")
}
