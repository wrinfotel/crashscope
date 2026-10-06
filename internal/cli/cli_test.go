package cli

import (
	"bytes"
	"strings"
	"testing"
)

func TestVersionFlag(t *testing.T) {
	var out, errb bytes.Buffer
	code := Run([]string{"crashscope", "--version"}, &out, &errb)
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
	if got := out.String(); !strings.Contains(got, "crashscope 0.1.0") {
		t.Fatalf("output %q, want version string", got)
	}
}

func TestNoArgsIsUsageError(t *testing.T) {
	var out, errb bytes.Buffer
	code := Run([]string{"crashscope"}, &out, &errb)
	if code != 3 {
		t.Fatalf("exit = %d, want 3 (usage error)", code)
	}
	if !strings.Contains(errb.String(), "Usage:") {
		t.Fatalf("stderr %q, want usage", errb.String())
	}
}
