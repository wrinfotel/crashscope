package report

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"crashscope/internal/classifier"
	"crashscope/internal/parser"
)

func TestRenderTextJni(t *testing.T) {
	raw, err := os.ReadFile("../parser/testdata/jdk17_jni_sigsegv.log")
	if err != nil {
		t.Fatal(err)
	}
	r, err := parser.Parse("hs_err_pid4711.log", raw)
	if err != nil {
		t.Fatal(err)
	}
	vs := classifier.Classify(r)

	var b bytes.Buffer
	if err := RenderText(&b, r, vs, false); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{
		"crashscope 0.1.0",
		"hs_err_pid4711.log",
		"Eclipse Temurin 17",
		"SIGSEGV (0xb)",
		"VERDICT [high]: SIGSEGV inside third-party native code (JNI)",
		"libsqlitejdbc.so",
		"FIX:",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("output missing %q:\n%s", want, out)
		}
	}
}

func TestRenderJSON(t *testing.T) {
	raw, _ := os.ReadFile("../parser/testdata/jdk17_jni_sigsegv.log")
	r, _ := parser.Parse("f.log", raw)
	vs := classifier.Classify(r)

	var b bytes.Buffer
	if err := RenderJSON(&b, r, vs); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v\n%s", err, b.String())
	}
	for _, key := range []string{"tool", "version", "file", "jdk", "signal", "verdicts"} {
		if _, ok := doc[key]; !ok {
			t.Fatalf("JSON missing key %q", key)
		}
	}
	jdk := doc["jdk"].(map[string]any)
	if jdk["major"].(float64) != 17 {
		t.Fatalf("jdk.major = %v", jdk["major"])
	}
	if doc["signal"] != "SIGSEGV (0xb)" {
		t.Fatalf("signal = %v", doc["signal"])
	}
}
