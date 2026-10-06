package parser

import (
	"strings"
	"testing"
)

// Tests over real-shape fixtures derived from public GitHub issues (see
// testcorpus/README.md for provenance). Real hs_err logs carry jvm_args,
// java_command and the Dynamic libraries list as plain blocks inside the
// P R O C E S S section — there is no "V M  A R G S" or "M A P" header.

func TestRealShapeLinuxPicard(t *testing.T) {
	r, err := Parse("testdata/real_linux_jdk8u192.log", readTestdata(t, "real_linux_jdk8u192.log"))
	if err != nil {
		t.Fatal(err)
	}
	if r.Section("VMARGS") != "" || r.Section("MAP") != "" {
		t.Fatalf("real log must have no VMARGS/MAP sections, got %q / %q",
			r.Section("VMARGS"), r.Section("MAP"))
	}
	if r.JVMArgs != "-Xmx200G" {
		t.Errorf("JVMArgs = %q, want -Xmx200G (must be found in PROCESS body)", r.JVMArgs)
	}
	if r.JavaCommand != "picard.jar MarkDuplicates VALIDATION_STRINGENCY=LENIENT" {
		t.Errorf("JavaCommand = %q", r.JavaCommand)
	}
	libs := strings.Join(r.Libraries, " ")
	if !strings.Contains(libs, "/opt/java8/jre/lib/amd64/server/libjvm.so") {
		t.Errorf("Libraries missing libjvm.so: %v", r.Libraries)
	}
	if !strings.Contains(libs, "/opt/glibc-2.24/lib/ld-2.24.so") {
		t.Errorf("Libraries missing ld-2.24.so: %v", r.Libraries)
	}
	if strings.Contains(libs, "[heap]") {
		t.Errorf("pseudo-path [heap] must not count as a library: %v", r.Libraries)
	}
	// F2: nameless VMThread with the id in a second bracket group.
	if r.CurrentThread.Kind != "VMThread" || r.CurrentThread.Name != "" || r.CurrentThread.ID != "21597" {
		t.Errorf("CurrentThread = %+v, want VMThread with empty name and id 21597", r.CurrentThread)
	}
	if r.JDKMajor != 8 {
		t.Errorf("JDKMajor = %d, want 8", r.JDKMajor)
	}
}

func TestRealShapeWindowsCorretto(t *testing.T) {
	r, err := Parse("testdata/real_windows_corretto8.log", readTestdata(t, "real_windows_corretto8.log"))
	if err != nil {
		t.Fatal(err)
	}
	if r.Section("VMARGS") != "" || r.Section("MAP") != "" {
		t.Fatalf("real log must have no VMARGS/MAP sections, got %q / %q",
			r.Section("VMARGS"), r.Section("MAP"))
	}
	if r.JVMArgs != "none" {
		t.Errorf("JVMArgs = %q, want \"none\" (from PROCESS body)", r.JVMArgs)
	}
	if r.JavaCommand != `C:\PerfmonAgent\ServerAgent-2.2.3\startAgent.bat\..\CMDRunner.jar --tool PerfMonAgent` {
		t.Errorf("JavaCommand = %q", r.JavaCommand)
	}
	// F1: real Windows Dynamic libraries lines are "0xSTART - 0xEND path"
	// (no size column) and must populate Modules/Libraries.
	sigar := `C:\PerfmonAgent\ServerAgent-2.2.3\lib\sigar-amd64-winnt.dll`
	libs := strings.Join(r.Libraries, " ")
	if !strings.Contains(libs, sigar) {
		t.Errorf("Libraries missing crashing dll %q: %v", sigar, r.Libraries)
	}
	if !strings.Contains(libs, `C:\Windows\SYSTEM32\ntdll.dll`) {
		t.Errorf("Libraries missing ntdll.dll: %v", r.Libraries)
	}
	if strings.Contains(libs, "java.exe") {
		t.Errorf("java.exe must not count as a native library: %v", r.Libraries)
	}
	if len(r.Modules) < 7 {
		t.Errorf("Modules = %d, want >= 7", len(r.Modules))
	}
	if r.CurrentThread.Name != "Thread-0" || r.CurrentThread.Kind != "JavaThread" ||
		r.CurrentThread.State != "_thread_in_native" || r.CurrentThread.ID != "560" {
		t.Errorf("CurrentThread = %+v", r.CurrentThread)
	}
	if r.Signal != "EXCEPTION_ACCESS_VIOLATION (0xc0000005)" {
		t.Errorf("Signal = %q", r.Signal)
	}
}
