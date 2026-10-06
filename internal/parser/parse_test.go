package parser

import (
	"strings"
	"testing"
)

func TestParseJdk17Full(t *testing.T) {
	r, err := Parse("testdata/jdk17_jni_sigsegv.log", readTestdata(t, "jdk17_jni_sigsegv.log"))
	if err != nil {
		t.Fatal(err)
	}
	if len(r.Modules) != 2 {
		t.Fatalf("Modules = %d, want 2", len(r.Modules))
	}
	if r.Modules[0].Path != "/opt/app/lib/libsqlitejdbc.so" {
		t.Fatalf("Modules[0].Path = %q", r.Modules[0].Path)
	}
	want := []string{"/opt/app/lib/libsqlitejdbc.so", "/usr/lib/jvm/temurin-17/lib/server/libjvm.so"}
	if len(r.Libraries) != len(want) {
		t.Fatalf("Libraries = %v, want %v", r.Libraries, want)
	}
	for i, w := range want {
		if r.Libraries[i] != w {
			t.Fatalf("Libraries[%d] = %q, want %q", i, r.Libraries[i], w)
		}
	}
	if r.GCName != "G1" {
		t.Fatalf("GCName = %q, want G1", r.GCName)
	}
	if r.OOMInEvents {
		t.Fatal("OOMInEvents = true, want false")
	}
}

func TestParseJdk8OOMMarkers(t *testing.T) {
	r, err := Parse("testdata/jdk8_native_oom.log", readTestdata(t, "jdk8_native_oom.log"))
	if err != nil {
		t.Fatal(err)
	}
	if !r.OOMInEvents {
		t.Fatal("OOMInEvents = false, want true")
	}
	if !strings.Contains(strings.Join(r.Libraries, " "), "libjvm.so") {
		t.Fatalf("Libraries missing libjvm: %v", r.Libraries)
	}
}
