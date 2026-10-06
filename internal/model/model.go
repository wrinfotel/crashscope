package model

import (
	"strings"
)

// Frame is one entry of a native or Java stack.
type Frame struct {
	Type string // V, C, J, j or v
	// Location is the frame target. Stack-frame lines keep the brackets for
	// native frames ("[libsqlitejdbc.so+0x6a2b]") and are bare for Java
	// frames ("org.sqlite.core.DB.prepare(...)V+8"); ProblemFrame.Location
	// (parsed from the prologue) has brackets trimmed.
	Location string
	Symbol   string // remainder of the line, e.g. "sqlite3_prepare_v2+0x3b"
}

// Thread is the crashing thread header from the THREAD section.
type Thread struct {
	Name  string // quoted thread name
	Kind  string // JavaThread, Thread, ...
	State string // _thread_in_native, _thread_in_Java, ...
	ID    string // OS tid
}

// MapEntry is one line of the memory map (PROC_MAPS).
type MapEntry struct {
	Start, End, Perms, Path string
}

// CrashReport is the typed view of one hs_err_pid file.
type CrashReport struct {
	Path     string
	Prologue string // raw text before the first "----- TITLE -----" line

	// Filled by header parsing (Task 3):
	Messages     []string // all non-empty prologue "#" lines, "# " stripped
	Signal       string   // "SIGSEGV (0xb)" or "EXCEPTION_ACCESS_VIOLATION (0xc0000005)"
	PC, PID, TID string
	JREVersion   string
	JVMVersion   string
	JDKVendor    string
	JDKMajor     int // 8, 11, 17, 21, 25; 0 if unknown
	ProblemFrame Frame
	OutsideJVM   bool // "The crash happened outside the Java Virtual Machine in native code."

	// Filled by THREAD/VM_ARGS/EVENTS parsing (Task 4):
	CurrentThread Thread
	NativeFrames  []Frame
	JavaFrames    []Frame
	SigInfo       string
	StackFreeKB   int // free space from the "Stack:" line; -1 if absent
	JVMArgs       string
	JavaCommand   string
	Events        []string

	// Filled by MAP/HEAP parsing (Task 5):
	Modules     []MapEntry
	Libraries   []string // unique native module paths
	GCName      string
	OOMInEvents bool

	// Filled by Split (this task):
	Sections     map[string]string // despaced upper-case key -> raw body
	SectionOrder []string
}

// Section returns the raw body of a section by its despaced upper-case key
// ("THREAD", "VMARGS", "MAP", ...), or "" if absent.
func (r *CrashReport) Section(key string) string {
	return r.Sections[strings.ToUpper(key)]
}
