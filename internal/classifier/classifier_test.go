package classifier

import (
	"os"
	"strings"
	"testing"

	"crashscope/internal/parser"
)

func TestClassifyJniCrash(t *testing.T) {
	raw, err := os.ReadFile("../parser/testdata/jdk17_jni_sigsegv.log")
	if err != nil {
		t.Fatal(err)
	}
	r, err := parser.Parse("f", raw)
	if err != nil {
		t.Fatal(err)
	}
	vs := Classify(r)
	if len(vs) == 0 || vs[0].ID != "sigsegv-jni" || vs[0].Confidence != "high" {
		t.Fatalf("verdicts = %+v", vs)
	}
	if len(vs[0].Fix) == 0 {
		t.Fatal("sigsegv-jni verdict has no fix steps")
	}
}

func TestClassifyNativeOOM(t *testing.T) {
	raw, err := os.ReadFile("../parser/testdata/jdk8_native_oom.log")
	if err != nil {
		t.Fatal(err)
	}
	r, err := parser.Parse("f", raw)
	if err != nil {
		t.Fatal(err)
	}
	vs := Classify(r)
	if len(vs) == 0 || vs[0].ID != "native-oom" {
		t.Fatalf("verdicts = %+v", vs)
	}
}

func TestClassifyStackOverflow(t *testing.T) {
	r, err := parser.Parse("f", []byte(soeLog))
	if err != nil {
		t.Fatal(err)
	}
	if vs := Classify(r); len(vs) == 0 || vs[0].ID != "stack-overflow" {
		t.Fatalf("verdicts = %+v", vs)
	}
}

func TestClassifyJitCrash(t *testing.T) {
	r, err := parser.Parse("f", []byte(jitLog))
	if err != nil {
		t.Fatal(err)
	}
	if vs := Classify(r); vs[0].ID != "jit-c2" {
		t.Fatalf("verdicts = %+v", vs)
	}
}

func TestClassifyGlibc(t *testing.T) {
	r, err := parser.Parse("f", []byte(glibcLog))
	if err != nil {
		t.Fatal(err)
	}
	if vs := Classify(r); vs[0].ID != "glibc-hardware" {
		t.Fatalf("verdicts = %+v", vs)
	}
}

// F3: a Picard-style cleanup line pasted above the log (bare "corrupted:",
// exactly how the surrounding snakemake output parses when a user saves the
// whole console paste as the .log file) must not trigger glibc-hardware.
func TestGlibcTriggerIgnoresBareCorrupted(t *testing.T) {
	r, err := parser.Parse("f", []byte(picardCleanupLog))
	if err != nil {
		t.Fatal(err)
	}
	for _, v := range Classify(r) {
		if v.ID == "glibc-hardware" {
			t.Fatalf("bare \"corrupted\" line must not trigger glibc-hardware: %+v", v)
		}
	}
}

// The JNI "loaded from <path>" evidence must also work for Windows library
// paths (backslash separators) on a real-shape log.
func TestClassifyRealShapeWindowsJniEvidence(t *testing.T) {
	raw, err := os.ReadFile("../parser/testdata/real_windows_corretto8.log")
	if err != nil {
		t.Fatal(err)
	}
	r, err := parser.Parse("f", raw)
	if err != nil {
		t.Fatal(err)
	}
	vs := Classify(r)
	if len(vs) == 0 || vs[0].ID != "sigsegv-jni" {
		t.Fatalf("verdicts = %+v", vs)
	}
	found := false
	for _, e := range vs[0].Evidence {
		if strings.HasPrefix(e, "loaded from ") && strings.Contains(e, "sigar-amd64-winnt.dll") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no \"loaded from\" evidence for the crashing dll: %+v", vs[0].Evidence)
	}
}

// Real-shape Linux log (VMThread, V libjvm frame) classifies as vm-internal;
// in particular the Picard log shape must not produce a glibc false positive.
func TestClassifyRealShapeLinuxVMInternal(t *testing.T) {
	raw, err := os.ReadFile("../parser/testdata/real_linux_jdk8u192.log")
	if err != nil {
		t.Fatal(err)
	}
	r, err := parser.Parse("f", raw)
	if err != nil {
		t.Fatal(err)
	}
	vs := Classify(r)
	if len(vs) == 0 || vs[0].ID != "vm-internal" {
		t.Fatalf("verdicts = %+v, want vm-internal", vs)
	}
	for _, v := range vs {
		if v.ID == "glibc-hardware" {
			t.Fatalf("real Picard log must not trigger glibc-hardware: %+v", vs)
		}
	}
}

func TestClassifyUnknownFallback(t *testing.T) {
	r, err := parser.Parse("f", []byte(unknownLog))
	if err != nil {
		t.Fatal(err)
	}
	vs := Classify(r)
	if len(vs) == 0 || vs[0].ID != "unknown" || vs[0].Confidence != "low" {
		t.Fatalf("verdicts = %+v", vs)
	}
}

func TestClassifyOomEventDoesNotBeatJni(t *testing.T) {
	r, err := parser.Parse("f", []byte(oomEventLog))
	if err != nil {
		t.Fatal(err)
	}
	vs := Classify(r)
	if len(vs) == 0 || vs[0].ID != "sigsegv-jni" || vs[0].Confidence != "high" {
		t.Fatalf("verdicts = %+v", vs)
	}
	found := false
	for _, v := range vs {
		if v.ID == "native-oom" {
			found = true
			if v.Confidence != "medium" {
				t.Fatalf("native-oom confidence = %q, want medium", v.Confidence)
			}
		}
	}
	if !found {
		t.Fatalf("native-oom verdict missing from %+v", vs)
	}
}

func TestClassifyJniTitleUsesRealSignal(t *testing.T) {
	r, err := parser.Parse("f", []byte(libcAbortLog))
	if err != nil {
		t.Fatal(err)
	}
	vs := Classify(r)
	if len(vs) == 0 || vs[0].ID != "sigsegv-jni" {
		t.Fatalf("verdicts = %+v", vs)
	}
	if !strings.Contains(vs[0].Title, "SIGABRT") || strings.Contains(vs[0].Title, "SIGSEGV") {
		t.Fatalf("title = %q, want SIGABRT without SIGSEGV", vs[0].Title)
	}
	if !strings.Contains(vs[0].Summary, "system library") {
		t.Fatalf("summary = %q, want system-library wording", vs[0].Summary)
	}
}

const soeLog = `#
# A fatal error has been detected by the Java Runtime Environment:
#
#  SIGSEGV (0xb) at pc=0x00007f0000000000, pid=1, tid=2
#
# JRE version: OpenJDK Runtime Environment Temurin-17.0.4.1+1 (17.0.4.1+1) (build 17.0.4.1+1)
# Java VM: OpenJDK 64-Bit Server VM Temurin-17.0.4.1+1 (17.0.4.1+1, mixed mode, tiered, g1 gc, linux-amd64)
#

---------------  T H R E A D  ------------

Current thread (0x00007f):  JavaThread "worker-3" [_thread_in_Java, id=9, stack(0x0,0x0)]

---------------  E V E N T S  ---------------
java.lang.StackOverflowError
`

const jitLog = `#
# A fatal error has been detected by the Java Runtime Environment:
#
#  SIGSEGV (0xb) at pc=0x00007f0000000000, pid=1, tid=2
#
# JRE version: OpenJDK Runtime Environment Temurin-17.0.4.1+1 (17.0.4.1+1) (build 17.0.4.1+1)
# Java VM: OpenJDK 64-Bit Server VM Temurin-17.0.4.1+1 (17.0.4.1+1, mixed mode, tiered, g1 gc, linux-amd64)
# Problematic frame:
# V  [libjvm.so+0x123456]  PhaseCFG::do_block+0x2a
#
# Internal Error (0x40000f4e), pid=1, tid=2
# Error: /build/jdk17u/src/hotspot/share/opto/parse1.cpp:1234, pid=1, tid=2
#

---------------  T H R E A D  ------------

Current thread (0x00007f):  JavaThread "C2 CompilerThread0" [_thread_in_native, id=9, stack(0x0,0x0)]
`

const glibcLog = `#
# A fatal error has been detected by the Java Runtime Environment:
#
#  SIGABRT (0x6) at pc=0x00007f0000000000, pid=1, tid=2
#
# JRE version: OpenJDK Runtime Environment Temurin-17.0.4.1+1 (17.0.4.1+1) (build 17.0.4.1+1)
# Java VM: OpenJDK 64-Bit Server VM Temurin-17.0.4.1+1 (17.0.4.1+1, mixed mode, g1 gc, linux-amd64)
#
# malloc(): corrupted top size
#

---------------  T H R E A D  ------------

Current thread (0x00007f):  JavaThread "main" [_thread_in_native, id=9, stack(0x0,0x0)]
`

// picardCleanupLog simulates a console paste saved as a .log file: the
// snakemake failure output (bare, non-# line with "corrupted:") comes before
// the hs_err prologue. Source shape: broadinstitute/picard#1501.
const picardCleanupLog = `Removing output files of failed job mark_duplicates since they might be corrupted: alignment/HG03583_S1_L001.sorted.dedupped.bam
Shutting down, this might take some time.
#
# A fatal error has been detected by the Java Runtime Environment:
#
#  SIGSEGV (0xb) at pc=0x00002b8c9ecb3d76, pid=21565, tid=0x00002bbede786700
#
# JRE version: Java(TM) SE Runtime Environment (8.0_192-b12) (build 1.8.0_192-b12)
# Java VM: Java HotSpot(TM) 64-Bit Server VM (25.192-b12 mixed mode linux-amd64 )
#

---------------  T H R E A D  ------------

Current thread (0x00002b8ca0096000): VMThread [stack: 0x00002bbede686000,0x00002bbede787000] [id=21597]
`

const unknownLog = `#
# A fatal error has been detected by the Java Runtime Environment:
#
#  SIGSEGV (0xb) at pc=0x00007f0000000000, pid=1, tid=2
#
# JRE version: OpenJDK Runtime Environment Temurin-25.0.1+8 (25.0.1+8) (build 25.0.1+8)
# Java VM: OpenJDK 64-Bit Server VM Temurin-25.0.1+8 (25.0.1+8, mixed mode, g1 gc, linux-amd64)
#

---------------  T H R E A D  ------------

Current thread (0x00007f):  JavaThread "main" [_thread_in_Java, id=9, stack(0x0,0x0)]
`

// oomEventLog is a SIGSEGV JNI crash whose Events merely record an earlier
// java.lang.OutOfMemoryError — the OOM must not outrank the JNI verdict.
const oomEventLog = `#
# A fatal error has been detected by the Java Runtime Environment:
#
#  SIGSEGV (0xb) at pc=0x00007f2c6b51a2b4, pid=4711, tid=4712
#
# JRE version: OpenJDK Runtime Environment Temurin-17.0.4.1+1 (17.0.4.1+1) (build 17.0.4.1+1)
# Java VM: OpenJDK 64-Bit Server VM Temurin-17.0.4.1+1 (17.0.4.1+1, mixed mode, tiered, g1 gc, linux-amd64)
# Problematic frame:
# C  [libsqlitejdbc.so+0x6a2b]  sqlite3_prepare_v2+0x3b
#
# The crash happened outside the Java Virtual Machine in native code.
#

---------------  T H R E A D  ------------

Current thread (0x00007f2c8802be80):  JavaThread "main" [_thread_in_native, id=4712, stack(0x00007f2c7f43c000,0x00007f2c7f53d000)]

Native frames: (J=compiled Java code, j=interpreted, Vv=VM code, C=native code)
C  [libsqlitejdbc.so+0x6a2b]  sqlite3_prepare_v2+0x3b
j  org.sqlite.core.NativeDB.prepare(Ljava/lang/String;)J+0

siginfo: si_signo: 11 (SIGSEGV), si_code: 1 (SEGV_MAPERR), si_addr: 0x0000000000000010

Java frames: (J=compiled Java code, j=interpreted, Vv=VM code, C=native code)
j  org.sqlite.core.NativeDB.prepare(Ljava/lang/String;)J+0

---------------  E V E N T S  ---------------
java.lang.OutOfMemoryError: unable to create native thread
`

// libcAbortLog is a SIGABRT crash inside the system library libc.
const libcAbortLog = `#
# A fatal error has been detected by the Java Runtime Environment:
#
#  SIGABRT (0x6) at pc=0x00007f1234567890, pid=4711, tid=4712
#
# JRE version: OpenJDK Runtime Environment Temurin-17.0.4.1+1 (17.0.4.1+1) (build 17.0.4.1+1)
# Java VM: OpenJDK 64-Bit Server VM Temurin-17.0.4.1+1 (17.0.4.1+1, mixed mode, tiered, g1 gc, linux-amd64)
# Problematic frame:
# C  [libc.so+0x35a2b]  raise+0x3b
#

---------------  T H R E A D  ------------

Current thread (0x00007f2c8802be80):  JavaThread "main" [_thread_in_native, id=4712, stack(0x00007f2c7f43c000,0x00007f2c7f53d000)]

Native frames: (J=compiled Java code, j=interpreted, Vv=VM code, C=native code)
C  [libc.so+0x35a2b]  raise+0x3b

siginfo: si_signo: 6 (SIGABRT), si_code: -6 (SI_TKILL)

---------------  V M  A R G S  ---------------
jvm_args: -Xmx2g
`
