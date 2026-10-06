package report

import (
	"fmt"
	"io"
	"strings"

	"crashscope/internal/classifier"
	"crashscope/internal/model"
	"crashscope/internal/version"
)

// RenderText writes the human-readable report.
func RenderText(w io.Writer, r *model.CrashReport, vs []classifier.Verdict, verbose bool) error {
	b := &strings.Builder{}
	fmt.Fprintf(b, "crashscope %s — offline JVM crash log analyzer\n\n", version.Version)
	fmt.Fprintf(b, "  File:    %s\n", r.Path)
	if r.JDKVendor == "" && r.JDKMajor == 0 {
		// JDK-7-era logs: vendor and major are unknown — print the raw
		// version string instead of "JVM: 0 —".
		fmt.Fprintf(b, "  JVM:     %s\n", trunc(r.JVMVersion, 100))
	} else {
		fmt.Fprintf(b, "  JVM:     %s %d — %s\n", r.JDKVendor, r.JDKMajor, trunc(r.JVMVersion, 100))
	}
	if r.Signal != "" {
		fmt.Fprintf(b, "  Signal:  %s at pc=%s in thread %q (%s)\n",
			r.Signal, r.PC, r.CurrentThread.Name, r.CurrentThread.State)
	}
	if r.GCName != "" {
		fmt.Fprintf(b, "  GC:      %s\n", r.GCName)
	}
	fmt.Fprintln(b)

	for i, v := range vs {
		marker := "VERDICT"
		if i > 0 {
			marker = "ALSO RELEVANT"
		}
		fmt.Fprintf(b, "%s [%s]: %s\n", marker, v.Confidence, v.Title)
		if v.Summary != "" {
			fmt.Fprintf(b, "  %s\n", v.Summary)
		}
		for _, e := range v.Evidence {
			fmt.Fprintf(b, "  evidence: %s\n", e)
		}
		for _, bug := range v.Bugs {
			fmt.Fprintf(b, "  known bug: %s — %s (%s)\n", bug.ID, bug.Summary, bug.URL)
		}
		if len(v.Fix) > 0 {
			fmt.Fprintln(b, "  FIX:")
			for j, f := range v.Fix {
				fmt.Fprintf(b, "    %d. %s\n", j+1, f)
			}
		}
		fmt.Fprintln(b)
	}

	if verbose {
		fmt.Fprintf(b, "  jvm_args: %s\n", r.JVMArgs)
		fmt.Fprintf(b, "  java_command: %s\n", r.JavaCommand)
		fmt.Fprintf(b, "  native libraries (%d):\n", len(r.Libraries))
		for _, lib := range r.Libraries {
			fmt.Fprintf(b, "    %s\n", lib)
		}
		fmt.Fprintf(b, "  recent events:\n")
		for i, e := range r.Events {
			if i >= len(r.Events)-10 {
				fmt.Fprintf(b, "    %s\n", e)
			}
		}
	} else {
		fmt.Fprintf(b, "  Details: run with --verbose (args, libraries, events) or --json\n")
	}
	_, err := io.WriteString(w, b.String())
	return err
}

func trunc(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "…"
}
