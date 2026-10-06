package main_test

import (
	"bytes"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func buildBin(t *testing.T) string {
	t.Helper()
	bin := filepath.Join(t.TempDir(), "crashscope_test.bin")
	// Test runs with cwd = cmd/crashscope, so "." is the main package.
	cmd := exec.Command("go", "build", "-o", bin, ".")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("build failed: %v\n%s", err, out)
	}
	return bin
}

func TestEndToEndSyntheticCorpus(t *testing.T) {
	bin := buildBin(t)
	files, err := filepath.Glob("../../testcorpus/synthetic/*.log")
	if err != nil || len(files) == 0 {
		t.Fatalf("glob: %v (%d files)", err, len(files))
	}
	for _, f := range files {
		// unrecognized.log is the exit-1 case, covered below.
		if filepath.Base(f) == "unrecognized.log" {
			continue
		}
		var out bytes.Buffer
		cmd := exec.Command(bin, "--json", f)
		cmd.Stdout = &out
		cmd.Stderr = os.Stderr
		code := 0
		if err := cmd.Run(); err != nil {
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else {
				t.Fatalf("%s: run: %v", f, err)
			}
		}
		if code != 0 {
			t.Errorf("%s: exit = %d, want 0 (recognized cause)", filepath.Base(f), code)
		}
		var doc map[string]any
		if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
			t.Errorf("%s: invalid JSON: %v", filepath.Base(f), err)
		}
	}
}

func TestEndToEndUnrecognized(t *testing.T) {
	bin := buildBin(t)
	f := filepath.Join("..", "..", "testcorpus", "synthetic", "unrecognized.log")
	var out bytes.Buffer
	cmd := exec.Command(bin, "--json", f)
	cmd.Stdout = &out
	cmd.Stderr = os.Stderr
	code := 0
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatalf("run: %v", err)
		}
	}
	if code != 1 {
		t.Fatalf("exit = %d, want 1 (parsed, pattern unrecognized)", code)
	}
	var doc map[string]any
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("invalid JSON: %v", err)
	}
}

func TestEndToEndGarbage(t *testing.T) {
	bin := buildBin(t)
	garbage := filepath.Join(t.TempDir(), "garbage.log")
	os.WriteFile(garbage, []byte("not a crash log\n"), 0o644)
	cmd := exec.Command(bin, garbage)
	if err := cmd.Run(); err == nil {
		t.Fatal("exit = 0, want 2")
	} else if ee, ok := err.(*exec.ExitError); !ok || ee.ExitCode() != 2 {
		t.Fatalf("exit err = %v, want code 2", err)
	}
}
