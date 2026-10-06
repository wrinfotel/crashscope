package parser

import (
	"testing"
)

func TestJDKMatrix(t *testing.T) {
	cases := []struct {
		fixture string
		major   int
		signal  string
	}{
		{"jdk8_native_oom.log", 8, ""},
		{"jdk17_jni_sigsegv.log", 17, "SIGSEGV (0xb)"},
		{"jdk11_sigsegv_v.log", 11, "SIGSEGV (0xb)"},
		{"jdk21_zgc.log", 21, "SIGSEGV (0xb)"},
		{"jdk25_latest.log", 25, "SIGSEGV (0xb)"},
		{"windows_av.log", 17, "EXCEPTION_ACCESS_VIOLATION (0xc0000005)"},
	}
	for _, c := range cases {
		r, err := Parse("testdata/"+c.fixture, readTestdata(t, c.fixture))
		if err != nil {
			t.Errorf("%s: %v", c.fixture, err)
			continue
		}
		if r.JDKMajor != c.major {
			t.Errorf("%s: JDKMajor = %d, want %d", c.fixture, r.JDKMajor, c.major)
		}
		if r.Signal != c.signal {
			t.Errorf("%s: Signal = %q, want %q", c.fixture, r.Signal, c.signal)
		}
		if r.CurrentThread.Name == "" {
			t.Errorf("%s: no crashing thread parsed", c.fixture)
		}
	}
}

// Brief Step 2: with the Windows module-list regex in place, Libraries for
// windows_av.log must contain both .dll modules.
func TestWindowsMemMap(t *testing.T) {
	r, err := Parse("testdata/windows_av.log", readTestdata(t, "windows_av.log"))
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		`C:\Program Files\Eclipse Adoptium\jdk-17.0.4.1.1-hotspot\bin\jvm.dll`,
		`C:\app\lib\app.dll`,
	}
	if len(r.Libraries) != len(want) {
		t.Fatalf("Libraries = %v, want %v", r.Libraries, want)
	}
	for i, w := range want {
		if r.Libraries[i] != w {
			t.Errorf("Libraries[%d] = %q, want %q", i, r.Libraries[i], w)
		}
	}
}
