package parser

import (
	"regexp"
	"strings"

	"crashscope/internal/model"
)

var (
	// "#  SIGSEGV (0xb) at pc=0x00007f..., pid=4711, tid=4712"
	// "# EXCEPTION_ACCESS_VIOLATION (0xc0000005) at pc=0x..., pid=..., tid=..."
	signalRe = regexp.MustCompile(`(?m)^#\s+(SIG\w+|EXCEPTION_\w+)\s+\((0x[0-9a-fA-F]+|\d+)\) at pc=(0x[0-9a-fA-F]+), pid=(\d+), tid=(\d+)`)
	jreRe    = regexp.MustCompile(`(?m)^#\s*JRE version:\s*(.*)$`)
	vmRe     = regexp.MustCompile(`(?m)^#\s*Java VM:\s*(.*)$`)
	// "# C  [libsqlitejdbc.so+0x6a2b]  sqlite3_prepare_v2+0x3b"
	// [ \t] (not \s) so the symbol never leaks text from the next line.
	frameRe = regexp.MustCompile(`(?m)^#[ \t]*([VCJjv])[ \t]+(\[[^\]]+\]|\S+)[ \t]*(.*)$`)
)

var vendors = []struct{ needle, name string }{
	{"temurin", "Eclipse Temurin"},
	{"adoptium", "Eclipse Temurin"},
	{"adoptopenjdk", "AdoptOpenJDK"},
	{"zulu", "Azul Zulu"},
	{"corretto", "Amazon Corretto"},
	{"graalvm", "GraalVM"},
	{"liberica", "BellSoft Liberica"},
	{"sapmachine", "SAP Machine"},
	{"oracle", "Oracle"},
	{"openjdk", "OpenJDK"},
}

// ParseHeader extracts signal, versions, vendor, JDK major and the
// problematic frame from the prologue.
func ParseHeader(r *model.CrashReport) error {
	for _, ln := range strings.Split(r.Prologue, "\n") {
		ln = strings.TrimPrefix(ln, "#")
		ln = strings.TrimSpace(ln)
		if ln != "" {
			r.Messages = append(r.Messages, ln)
		}
	}
	if m := signalRe.FindStringSubmatch(r.Prologue); m != nil {
		r.Signal = m[1] + " (" + m[2] + ")"
		r.PC, r.PID, r.TID = m[3], m[4], m[5]
	}
	if m := jreRe.FindStringSubmatch(r.Prologue); m != nil {
		r.JREVersion = strings.TrimSpace(m[1])
	}
	if m := vmRe.FindStringSubmatch(r.Prologue); m != nil {
		r.JVMVersion = strings.TrimSpace(m[1])
	}
	if m := frameRe.FindStringSubmatch(r.Prologue); m != nil {
		// model.Frame.Location stores the location without the "[...]"
		// wrapper, e.g. "libsqlitejdbc.so+0x6a2b".
		r.ProblemFrame = model.Frame{Type: m[1], Location: strings.Trim(m[2], "[]"), Symbol: strings.TrimSpace(m[3])}
	}
	r.OutsideJVM = strings.Contains(r.Prologue,
		"The crash happened outside the Java Virtual Machine in native code.")

	version := r.JVMVersion + " " + r.JREVersion
	lower := strings.ToLower(version)
	for _, v := range vendors {
		if strings.Contains(lower, v.needle) {
			r.JDKVendor = v.name
			break
		}
	}
	r.JDKMajor = jdkMajor(version)
	return nil
}

var (
	jdkMajorRe = regexp.MustCompile(`\b(\d{1,2})\.\d+\.\d+`)
)

// jdkMajor pulls the JDK feature number out of a raw version string;
// JDK 8 logs report "1.8.0_392" or "8.0_392".
func jdkMajor(version string) int {
	if strings.Contains(version, "1.8.0") || strings.Contains(version, " 8.0_") {
		return 8
	}
	if m := jdkMajorRe.FindStringSubmatch(version); m != nil {
		n := 0
		for _, c := range m[1] {
			n = n*10 + int(c-'0')
		}
		if n >= 8 && n <= 40 {
			return n
		}
	}
	return 0
}
