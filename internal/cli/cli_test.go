package cli

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// errWriter fails every write, simulating an unusable stdout (closed pipe,
// disk full). The report itself renders into an in-memory string first, so
// any render error is a write error.
type errWriter struct{ err error }

func (w errWriter) Write(p []byte) (int, error) { return 0, w.err }

func writeTempLog(t *testing.T) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "hs_err.log")
	const log = "#\n# A fatal error has been detected by the Java Runtime Environment:\n#\n" +
		"#  SIGSEGV (0xb) at pc=0x1, pid=1, tid=2\n#\n"
	if err := os.WriteFile(path, []byte(log), 0o644); err != nil {
		t.Fatal(err)
	}
	return path
}

// A reader closing stdout early (`crashscope f | head`) must not be reported
// as exit 2 "not an hs_err file" — the file parsed fine.
func TestBrokenPipeStdoutIsNotFileError(t *testing.T) {
	path := writeTempLog(t)
	var errb bytes.Buffer
	code := Run([]string{"crashscope", path}, errWriter{errors.New("write |stdout: broken pipe")}, &errb)
	if code != 0 {
		t.Fatalf("exit = %d, want 0", code)
	}
}

func TestOtherRenderErrorIsNotFileError(t *testing.T) {
	path := writeTempLog(t)
	var errb bytes.Buffer
	code := Run([]string{"crashscope", path}, errWriter{errors.New("disk full")}, &errb)
	if code != 1 {
		t.Fatalf("exit = %d, want 1", code)
	}
	if !strings.Contains(errb.String(), "render") {
		t.Fatalf("stderr = %q, want a render error mention", errb.String())
	}
}

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

func TestUnknownFlagIsUsageError(t *testing.T) {
	var out, errb bytes.Buffer
	code := Run([]string{"crashscope", "--foo"}, &out, &errb)
	if code != 3 {
		t.Fatalf("exit = %d, want 3 (usage error)", code)
	}
	if !strings.Contains(errb.String(), "Usage:") {
		t.Fatalf("stderr %q, want usage", errb.String())
	}
	if !strings.Contains(errb.String(), "--foo") {
		t.Fatalf("stderr %q, wants to name the bad flag", errb.String())
	}
	if out.String() != "" {
		t.Fatalf("stdout = %q, want empty", out.String())
	}
}
