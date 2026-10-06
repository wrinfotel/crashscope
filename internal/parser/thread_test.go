package parser

import (
	"strings"
	"testing"

	"crashscope/internal/model"
)

func loadParsed(t *testing.T, fixture string) *model.CrashReport {
	t.Helper()
	r, err := Split(fixture, readTestdata(t, fixture))
	if err != nil {
		t.Fatal(err)
	}
	if err := ParseHeader(r); err != nil {
		t.Fatal(err)
	}
	if err := ParseThread(r); err != nil {
		t.Fatal(err)
	}
	if err := ParseVMArgs(r); err != nil {
		t.Fatal(err)
	}
	return r
}

func TestThreadJdk17(t *testing.T) {
	r := loadParsed(t, "jdk17_jni_sigsegv.log")

	if r.CurrentThread.Name != "main" || r.CurrentThread.Kind != "JavaThread" ||
		r.CurrentThread.State != "_thread_in_native" || r.CurrentThread.ID != "4712" {
		t.Fatalf("CurrentThread = %+v", r.CurrentThread)
	}
	if len(r.NativeFrames) != 5 {
		t.Fatalf("NativeFrames = %d, want 5: %+v", len(r.NativeFrames), r.NativeFrames)
	}
	first := r.NativeFrames[0]
	if first.Type != "C" || first.Location != "[libsqlitejdbc.so+0x6a2b]" || first.Symbol != "sqlite3_prepare_v2+0x3b" {
		t.Fatalf("first native frame = %+v", first)
	}
	jf := r.NativeFrames[1]
	if jf.Type != "j" || jf.Location != "org.sqlite.core.NativeDB.prepare(Ljava/lang/String;)J+0" {
		t.Fatalf("second frame = %+v", jf)
	}
	if len(r.JavaFrames) != 4 {
		t.Fatalf("JavaFrames = %d, want 4", len(r.JavaFrames))
	}
	if !strings.Contains(r.SigInfo, "si_signo: 11 (SIGSEGV)") {
		t.Fatalf("SigInfo = %q", r.SigInfo)
	}
	if r.StackFreeKB != 1011 {
		t.Fatalf("StackFreeKB = %d, want 1011", r.StackFreeKB)
	}
	if r.JVMArgs != "-Xmx4g -Dapp.env=prod" || r.JavaCommand != "app.jar" {
		t.Fatalf("args = %q / %q", r.JVMArgs, r.JavaCommand)
	}
	if len(r.Events) == 0 || !strings.Contains(r.Events[len(r.Events)-1], "start.sh") {
		t.Fatalf("Events = %v", r.Events)
	}
}

func TestThreadJdk8(t *testing.T) {
	r := loadParsed(t, "jdk8_native_oom.log")
	if r.CurrentThread.State != "_thread_in_native" {
		t.Fatalf("state = %q", r.CurrentThread.State)
	}
}
