package classifier

import (
	"strings"

	"crashscope/internal/model"
)

type ruleFunc func(r *model.CrashReport) (*Verdict, bool)

// rules are evaluated in order; within equal confidence, earlier rules
// appear earlier in the report.
var rules = []ruleFunc{
	ruleNativeOOM,
	ruleStackOverflow,
	ruleJITCrash,
	ruleVMAssert,
	ruleJniCrash,
	ruleVMInternal,
	ruleGlibcHardware,
}

func allText(r *model.CrashReport) string {
	return strings.Join(r.Messages, " ") + " " + r.SigInfo + " " + strings.Join(r.Events, " ")
}

// anyContains reports whether any single line contains the needle.
func anyContains(lines []string, needle string) bool {
	for _, ln := range lines {
		if strings.Contains(ln, needle) {
			return true
		}
	}
	return false
}

func ruleNativeOOM(r *model.CrashReport) (*Verdict, bool) {
	triggers := []string{
		"insufficient memory for the Java Runtime Environment",
		"Native memory allocation",
		"std::bad_alloc",
		"Cannot allocate memory",
		"out of swap space",
		"unable to create native thread",
	}
	// A trigger in the prologue messages is definitive: the OOM itself killed
	// the process. A trigger only in events/siginfo records an earlier OOM
	// that the log merely mentions — downgrade to medium so a rule pinpointing
	// the actual crash frame can win the tie.
	hit := ""
	conf := "medium"
	for _, t := range triggers {
		if anyContains(r.Messages, t) {
			hit, conf = t, "high"
			break
		}
	}
	if hit == "" {
		for _, t := range triggers {
			if strings.Contains(r.SigInfo, t) || anyContains(r.Events, t) {
				hit = t
				break
			}
		}
	}
	if hit == "" {
		return nil, false
	}
	v := &Verdict{
		ID:         "native-oom",
		Title:      "Native (off-heap) memory exhaustion",
		Confidence: conf,
		Summary:    "The JVM could not get memory from the OS. Trigger marker: \"" + hit + "\".",
		Fix: []string{
			"Check OS-level limits: cgroup/container memory cap, RLIMIT_AS, swap and overcommit settings.",
			"Leave headroom: total -Xmx + direct buffers + metaspace + thread stacks must fit the container limit (a common failure is -Xmx close to the pod limit).",
			"Enable -XX:NativeMemoryTracking=summary and compare process RSS against -Xmx to find what eats native memory.",
			"On glibc under heavy thread churn, set MALLOC_ARENA_MAX=2 (glibc < 2.10 arenas blowup).",
			"If 'unable to create native thread': lower thread count or -Xss, or raise the OS threads limit (ulimit -u).",
		},
	}
	for _, m := range r.Messages {
		if strings.Contains(m, "insufficient memory") || strings.Contains(m, "Native memory allocation") {
			v.Evidence = append(v.Evidence, m)
		}
	}
	if r.OOMInEvents && strings.Contains(r.JVMArgs, "OnOutOfMemoryError") {
		v.Evidence = append(v.Evidence, "jvm_args contains OnOutOfMemoryError — a Java-level OOM was escalated into process death on purpose")
	}
	return v, true
}

func ruleStackOverflow(r *model.CrashReport) (*Verdict, bool) {
	txt := allText(r)
	if !(strings.Contains(txt, "StackOverflow") || strings.Contains(txt, "stack overflow")) {
		return nil, false
	}
	v := &Verdict{
		ID:         "stack-overflow",
		Title:      "Stack overflow (unbounded recursion)",
		Confidence: "high",
		Summary:    "The stack ran out: either Java recursion or a deep native call chain.",
		Fix: []string{
			"Look at the Java frames in the report: a repeated frame name is the recursion — fix the missing base case.",
			"If the recursion is legitimate, raise -Xss (per-thread stack size) and re-check -Xmx headroom.",
			"JNI recursion or huge native frames: the crashing thread's 'free space' in the THREAD section shows how little was left.",
		},
	}
	for _, e := range r.Events {
		if strings.Contains(e, "StackOverflow") {
			v.Evidence = append(v.Evidence, e)
		}
	}
	return v, true
}

func ruleJITCrash(r *model.CrashReport) (*Verdict, bool) {
	txt := allText(r)
	internal := strings.Contains(txt, "Internal Error")
	opto := strings.Contains(txt, "opto") || strings.Contains(txt, "c2_") || strings.Contains(txt, "compile")
	compileTask := false
	for _, f := range r.NativeFrames {
		if strings.Contains(f.Symbol, "Compile::") || strings.Contains(f.Location, "CompileBroker") {
			compileTask = true
		}
	}
	if !internal && !compileTask {
		return nil, false
	}
	if internal && !opto && !compileTask {
		return nil, false // generic VM assert, handled by ruleVMAssert
	}
	v := &Verdict{
		ID:         "jit-c2",
		Title:      "JIT compiler (C2) crash",
		Confidence: "high",
		Summary:    "The crash is inside the HotSpot optimizing compiler, not your code.",
		Fix: []string{
			"Update the JDK: C2 crashes are JVM bugs and get backported to CPU releases.",
			"Immediate workaround: -XX:CompileCommand=exclude,<class>.<method> for the method in the crash frame.",
			"Broader workaround: -XX:TieredStopAtLevel=1 (C1 only) — slower, but stops C2 from compiling anything.",
		},
		Evidence: evidenceContaining(r, "Internal Error"),
	}
	return v, true
}

func ruleVMAssert(r *model.CrashReport) (*Verdict, bool) {
	txt := allText(r)
	if !strings.Contains(txt, "Internal Error") {
		return nil, false
	}
	v := &Verdict{
		ID:         "vm-assert",
		Title:      "JVM internal assertion (guarantee/check failed)",
		Confidence: "medium",
		Summary:    "A JVM-internal consistency check fired. Usually a JDK bug; occasionally triggered by corrupted state.",
		Fix: []string{
			"Update to the latest CPU of your JDK line and re-test.",
			"Search bugs.openjdk.org for the file:line from the Internal Error line — often a known issue.",
			"If reproducible on the latest CPU, file it upstream with this hs_err attached.",
		},
		Evidence: evidenceContaining(r, "Internal Error"),
	}
	return v, true
}

func ruleJniCrash(r *model.CrashReport) (*Verdict, bool) {
	f := r.ProblemFrame
	if f.Type != "C" || f.Location == "" {
		return nil, false
	}
	lib := strings.Trim(f.Location, "[]")
	lib = strings.SplitN(lib, "+", 2)[0]
	if lib == "libjvm.so" || lib == "jvm.dll" || lib == "libjvm.dylib" {
		return nil, false // JVM's own frame — ruleVMInternal
	}
	if !r.OutsideJVM && r.CurrentThread.State != "_thread_in_native" && !strings.HasSuffix(lib, ".so") {
		return nil, false
	}
	summary := "The faulting instruction belongs to native library " + lib + ", called from Java via JNI."
	if isSystemLibrary(lib) {
		summary = "The faulting instruction belongs to the system library " + lib + ", called from Java via JNI."
	}
	v := &Verdict{
		ID:         "sigsegv-jni",
		Title:      jniCrashTitle(r.Signal),
		Confidence: "high",
		Summary:    summary,
		Fix: []string{
			"Upgrade " + lib + " to the latest release — check its own issue tracker for this crash signature.",
			"Verify the library matches your platform/arch and was built against a compatible toolchain.",
			"Run once with -Xcheck:jni to catch JNI contract violations (wrong local refs, missing exception checks).",
			"If it is an in-house JNI/FFI wrapper: audit argument types and lifetimes around the crashing call.",
		},
		Evidence: []string{"Problematic frame: " + f.Type + " [" + lib + "] " + f.Symbol},
	}
	for i, jf := range r.JavaFrames {
		if i < 3 && jf.Type == "j" {
			v.Evidence = append(v.Evidence, "called from Java: "+jf.Location)
		}
	}
	for _, m := range r.Modules {
		if strings.HasSuffix(m.Path, "/"+lib) {
			v.Evidence = append(v.Evidence, "loaded from "+m.Path)
		}
	}
	return v, true
}

// jniCrashTitle names the actual fatal signal instead of assuming SIGSEGV.
func jniCrashTitle(signal string) string {
	signal = strings.TrimSpace(signal)
	if signal == "" {
		return "Fatal error inside native library (JNI)"
	}
	if strings.HasPrefix(signal, "SIGSEGV") {
		return "SIGSEGV inside third-party native code (JNI)"
	}
	return strings.Fields(signal)[0] + " inside native code (JNI)"
}

// isSystemLibrary reports whether lib is an OS-level library rather than
// application or third-party code.
func isSystemLibrary(lib string) bool {
	if lib == "libc.so" {
		return true
	}
	for _, p := range []string{"libc", "ld-", "libSystem", "libpthread", "libm"} {
		if strings.HasPrefix(lib, p) {
			return true
		}
	}
	return false
}

func ruleVMInternal(r *model.CrashReport) (*Verdict, bool) {
	f := r.ProblemFrame
	isVM := f.Type == "V" ||
		(f.Type == "C" && strings.HasPrefix(strings.Trim(f.Location, "[]"), "libjvm.so"))
	if !isVM {
		return nil, false
	}
	v := &Verdict{
		ID:         "vm-internal",
		Title:      "Crash inside the JVM itself (libjvm)",
		Confidence: "medium",
		Summary:    "The faulting frame is HotSpot VM code. Most often a fixed JVM bug for your version.",
		Fix: []string{
			"Update to the latest CPU release of your JDK line, then re-test.",
			"Search bugs.openjdk.org for the frame symbol + your JDK version.",
			"If it reproduces on the latest CPU, report upstream (https://bugreport.java.com) with this file.",
		},
		Evidence: []string{"Problematic frame: " + f.Type + " [" + f.Location + "] " + f.Symbol},
	}
	return v, true
}

func ruleGlibcHardware(r *model.CrashReport) (*Verdict, bool) {
	triggers := []string{
		"malloc():", "free():", "corrupted", "double free", "invalid pointer",
		"glibc detected", "Machine check", "hardware error",
	}
	txt := allText(r)
	for _, t := range triggers {
		if strings.Contains(txt, t) {
			return &Verdict{
				ID:         "glibc-hardware",
				Title:      "Heap corruption or faulty memory (glibc/OS diagnostics)",
				Confidence: "medium",
				Summary:    "The C-level allocator reported corruption. Real causes: a native library bug, or failing RAM.",
				Fix: []string{
					"Run memtest86+ (or the vendor ECC log) on the host — allocator corruption is a classic bad-RAM symptom.",
					"Correlate: do crashes wander across unrelated libraries and stack traces? Wandering = suspect hardware.",
					"Update glibc and the native libraries in use; a double-free in one library corrupts the shared heap.",
					"Check dmesg for OOM-killer activity and EDAC/ECC reports around the crash time.",
				},
				Evidence: evidenceContaining(r, t),
			}, true
		}
	}
	return nil, false
}

// evidenceContaining returns up to 3 real quoted log lines containing the
// needle. allText() joins its parts with spaces and contains no newlines,
// so the lines are recovered from the prologue messages, the events and the
// siginfo line individually instead of by splitting the joined text.
func evidenceContaining(r *model.CrashReport, needle string) []string {
	var out []string
	for _, ln := range r.Messages {
		if strings.Contains(ln, needle) {
			out = append(out, strings.TrimSpace(ln))
			if len(out) >= 3 {
				return out
			}
		}
	}
	for _, ln := range r.Events {
		if strings.Contains(ln, needle) {
			out = append(out, strings.TrimSpace(ln))
			if len(out) >= 3 {
				return out
			}
		}
	}
	if len(out) < 3 && strings.Contains(r.SigInfo, needle) {
		out = append(out, strings.TrimSpace(r.SigInfo))
	}
	return out
}
