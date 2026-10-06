package report

import (
	"bytes"
	"encoding/json"
	"os"
	"strings"
	"testing"

	"crashscope/internal/classifier"
	"crashscope/internal/model"
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

// L23: nested verdict objects must use snake_case keys, not Go field names.
func TestRenderJSONVerdictSnakeCase(t *testing.T) {
	raw, _ := os.ReadFile("../parser/testdata/jdk17_jni_sigsegv.log")
	r, _ := parser.Parse("f.log", raw)
	vs := classifier.Classify(r)

	var b bytes.Buffer
	if err := RenderJSON(&b, r, vs); err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	v0 := doc["verdicts"].([]any)[0].(map[string]any)
	for _, key := range []string{"id", "title", "confidence", "summary", "fix", "evidence", "bugs"} {
		if _, ok := v0[key]; !ok {
			t.Fatalf("verdict JSON missing key %q: %v", key, v0)
		}
	}
	if _, ok := v0["ID"]; ok {
		t.Fatalf("verdict JSON leaks Go field name \"ID\": %v", v0)
	}
	if v0["id"] != "sigsegv-jni" {
		t.Fatalf("verdict id = %v", v0["id"])
	}
}

// L25: nil Evidence/Fix/Bugs must marshal as empty arrays, never null
// (the unknown/exit-1 path is the most common CI result).
func TestRenderJSONNoNulls(t *testing.T) {
	raw, err := os.ReadFile("../../testcorpus/synthetic/unrecognized.log")
	if err != nil {
		t.Fatal(err)
	}
	r, _ := parser.Parse("f.log", raw)
	vs := classifier.Classify(r)
	if vs[0].ID != "unknown" {
		t.Fatalf("precondition: want unknown verdict, got %s", vs[0].ID)
	}

	var b bytes.Buffer
	if err := RenderJSON(&b, r, vs); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "null") {
		t.Fatalf("JSON contains null:\n%s", b.String())
	}
	var doc map[string]any
	if err := json.Unmarshal(b.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
	v0 := doc["verdicts"].([]any)[0].(map[string]any)
	if ev, ok := v0["evidence"].([]any); !ok || len(ev) != 0 {
		t.Fatalf("evidence = %v, want []", v0["evidence"])
	}
	if bugs, ok := v0["bugs"].([]any); !ok || len(bugs) != 0 {
		t.Fatalf("bugs = %v, want []", v0["bugs"])
	}
	if fixes, ok := v0["fix"].([]any); !ok || len(fixes) == 0 {
		t.Fatalf("fix = %v, want non-empty array", v0["fix"])
	}
}

// F5: JDK-7-era logs (no vendor, major 0) must print the raw JVM version
// instead of "JVM: 0 —".
func TestRenderTextJDK7EraJVMLine(t *testing.T) {
	r := &model.CrashReport{
		Path:       "hs_err_pid100.log",
		JVMVersion: "Java HotSpot(TM) 64-Bit Server VM (24.79-b02 mixed mode linux-amd64 compressed oops)",
	}
	var b bytes.Buffer
	if err := RenderText(&b, r, nil, false); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	if strings.Contains(out, "JVM:      0 —") {
		t.Fatalf("JVM line renders major 0: %s", out)
	}
	if !strings.Contains(out, "JVM:     Java HotSpot(TM) 64-Bit Server VM (24.79-b02") {
		t.Fatalf("JVM line missing raw version string:\n%s", out)
	}
}
