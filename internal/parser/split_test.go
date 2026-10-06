package parser

import (
	"os"
	"strings"
	"testing"
)

func readTestdata(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestSplitJdk17(t *testing.T) {
	r, err := Split("testdata/jdk17_jni_sigsegv.log", readTestdata(t, "jdk17_jni_sigsegv.log"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.Prologue, "# A fatal error has been detected") {
		t.Fatalf("prologue missing fatal error line: %q", r.Prologue[:80])
	}
	if got := r.Section("THREAD"); !strings.Contains(got, "Current thread") {
		t.Fatalf("THREAD section missing: %q", got)
	}
	if r.Section("SUMMARY") == "" || r.Section("VMARGS") == "" || r.Section("MAP") == "" || r.Section("EVENTS") == "" {
		t.Fatalf("missing sections, got order %v", r.SectionOrder)
	}
	if r.SectionOrder[0] != "SUMMARY" {
		t.Fatalf("first section = %q, want SUMMARY", r.SectionOrder[0])
	}
}

func TestSplitJdk8(t *testing.T) {
	r, err := Split("testdata/jdk8_native_oom.log", readTestdata(t, "jdk8_native_oom.log"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(r.Prologue, "insufficient memory for the Java Runtime Environment") {
		t.Fatal("OOM prologue missing")
	}
}

func TestSplitRejectsGarbage(t *testing.T) {
	_, err := Split("garbage.log", []byte("hello world\nthis is not a crash log\n"))
	if err == nil || !strings.Contains(err.Error(), "not an hs_err_pid log") {
		t.Fatalf("err = %v, want not-an-hs_err error", err)
	}
}

// Section headers alone are not an hs_err fingerprint: the prologue "#"
// block with its fatal-error (or OOM) message is present in every real log
// and must be required even when the file has section headers.
func TestSplitRejectsSectionsWithoutPrologueMarker(t *testing.T) {
	fake := "---------------  F O O  ---------------\nsome text\n" +
		"---------------  B A R  ---------------\nmore text\n"
	_, err := Split("fake.log", []byte(fake))
	if err == nil || !strings.Contains(err.Error(), "not an hs_err_pid log") {
		t.Fatalf("err = %v, want not-an-hs_err error", err)
	}
}
