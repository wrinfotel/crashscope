package parser

import (
	"regexp"
	"strconv"
	"strings"

	"crashscope/internal/model"
)

var (
	// Current thread line variants seen in real logs:
	//   Current thread (0x00007f2c8802be80):  JavaThread "main" [_thread_in_native, id=4712, stack(...)]
	//   Current thread (0x00007f1bc0117800): JavaThread "C2 CompilerThread0" daemon [_thread_in_native, id=30354, stack(...)]
	//   Current thread (0x00002b8ca0096000): VMThread [stack: 0x00002bbede686000,0x00002bbede787000] [id=21597]
	// The quoted name and attributes between it and the bracket are optional;
	// some thread kinds put the id in a second bracket group.
	curThreadRe = regexp.MustCompile(
		`(?m)^Current thread \(0x[0-9a-fA-F]+\):\s+(\S+)(?:\s+"([^"\n]*)")?[^[\n]*\[([^\]]+)\](?:\s+\[([^\]]+)\])?`)
	frameLineRe = regexp.MustCompile(`^\s*([VCJjv])\s+(\[[^\]]+\]|\S+)\s*(.*)$`)
	// [ \t]* (not \s*) so a bare "siginfo:" line cannot capture the next line.
	sigInfoRe   = regexp.MustCompile(`(?m)^siginfo:[ \t]*(.*)$`)
	stackFreeRe = regexp.MustCompile(`(?m)^Stack:\s*\[0x[0-9a-fA-F]+,0x[0-9a-fA-F]+\],\s*sp=0x[0-9a-fA-F]+,\s*free space=(\d+)k`)
)

// ParseThread fills CurrentThread, NativeFrames, JavaFrames, SigInfo and
// StackFreeKB from the THREAD section.
func ParseThread(r *model.CrashReport) error {
	body := r.Section("THREAD")

	if m := curThreadRe.FindStringSubmatch(body); m != nil {
		r.CurrentThread = model.Thread{Kind: m[1], Name: m[2]}
		attrs := m[3]
		if m[4] != "" {
			attrs += ", " + m[4]
		}
		for _, part := range strings.Split(attrs, ",") {
			part = strings.TrimSpace(part)
			switch {
			case strings.HasPrefix(part, "id="):
				r.CurrentThread.ID = strings.TrimPrefix(part, "id=")
			case strings.HasPrefix(part, "_thread"):
				r.CurrentThread.State = part
			}
		}
	}
	if m := sigInfoRe.FindStringSubmatch(body); m != nil {
		r.SigInfo = strings.TrimSpace(m[1])
	}
	if m := stackFreeRe.FindStringSubmatch(body); m != nil {
		n, _ := strconv.Atoi(m[1])
		r.StackFreeKB = n
	}

	mode := 0 // 0 none, 1 native frames, 2 java frames
	for _, ln := range strings.Split(body, "\n") {
		if strings.HasPrefix(ln, "Native frames:") {
			mode = 1
			continue
		}
		if strings.HasPrefix(ln, "Java frames:") {
			mode = 2
			continue
		}
		if mode == 0 {
			continue
		}
		m := frameLineRe.FindStringSubmatch(ln)
		// Skip "v  ~StubRoutines::call_stub" marker lines: they are not real
		// frames (capital "V" VM frames are kept).
		if m == nil || m[1] == "v" {
			continue
		}
		f := model.Frame{Type: m[1], Location: m[2], Symbol: strings.TrimSpace(m[3])}
		if mode == 1 {
			r.NativeFrames = append(r.NativeFrames, f)
		} else {
			r.JavaFrames = append(r.JavaFrames, f)
		}
	}
	return nil
}
