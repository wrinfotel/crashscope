package parser

import (
	"testing"
)

func TestHeaderJdk17(t *testing.T) {
	r, err := Split("f", readTestdata(t, "jdk17_jni_sigsegv.log"))
	if err != nil {
		t.Fatal(err)
	}
	if err := ParseHeader(r); err != nil {
		t.Fatal(err)
	}

	if r.Signal != "SIGSEGV (0xb)" {
		t.Fatalf("Signal = %q", r.Signal)
	}
	if r.PC != "0x00007f2c6b51a2b4" || r.PID != "4711" || r.TID != "4712" {
		t.Fatalf("pc/pid/tid = %q/%q/%q", r.PC, r.PID, r.TID)
	}
	if r.JDKMajor != 17 {
		t.Fatalf("JDKMajor = %d, want 17", r.JDKMajor)
	}
	if r.JDKVendor != "Eclipse Temurin" {
		t.Fatalf("JDKVendor = %q", r.JDKVendor)
	}
	if r.ProblemFrame.Type != "C" ||
		r.ProblemFrame.Location != "libsqlitejdbc.so+0x6a2b" ||
		r.ProblemFrame.Symbol != "sqlite3_prepare_v2+0x3b" {
		t.Fatalf("ProblemFrame = %+v", r.ProblemFrame)
	}
	if !r.OutsideJVM {
		t.Fatal("OutsideJVM = false, want true")
	}
	found := false
	for _, m := range r.Messages {
		if m == "A fatal error has been detected by the Java Runtime Environment:" {
			found = true
		}
	}
	if !found {
		t.Fatalf("Messages = %v", r.Messages)
	}
}

// L7: the problematic-frame symbol must never leak text from the next line.
func TestFrameSymbolNoCrossLineJunk(t *testing.T) {
	raw := []byte("#\n# A fatal error has been detected by the Java Runtime Environment:\n#\n" +
		"#  SIGSEGV (0xb) at pc=0x00007f0000000000, pid=1, tid=2\n#\n" +
		"# JRE version: OpenJDK Runtime Environment Temurin-17.0.4.1+1 (17.0.4.1+1) (build 17.0.4.1+1)\n" +
		"# Java VM: OpenJDK 64-Bit Server VM Temurin-17.0.4.1+1 (17.0.4.1+1, mixed mode, g1 gc, linux-amd64)\n" +
		"# Problematic frame:\n" +
		"# C  [libfoo.so+0x1]\n" +
		"#\n\n")
	r, err := Split("f", raw)
	if err != nil {
		t.Fatal(err)
	}
	if err := ParseHeader(r); err != nil {
		t.Fatal(err)
	}
	if r.ProblemFrame.Symbol != "" {
		t.Fatalf("ProblemFrame.Symbol = %q, want empty (no cross-line junk)", r.ProblemFrame.Symbol)
	}
}

func TestHeaderJdk8(t *testing.T) {
	r, err := Split("f", readTestdata(t, "jdk8_native_oom.log"))
	if err != nil {
		t.Fatal(err)
	}
	if err := ParseHeader(r); err != nil {
		t.Fatal(err)
	}

	if r.JDKMajor != 8 {
		t.Fatalf("JDKMajor = %d, want 8", r.JDKMajor)
	}
	if r.Signal != "" {
		t.Fatalf("Signal = %q, want empty (OOM logs have no signal line)", r.Signal)
	}
	if len(r.Messages) == 0 || r.Messages[0] != "There is insufficient memory for the Java Runtime Environment to continue." {
		t.Fatalf("Messages[0] = %v", r.Messages)
	}
}
