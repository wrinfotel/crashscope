package parser

import (
	"regexp"
	"strconv"
	"strings"

	"crashscope/internal/model"
)

var (
	// Current thread (0x00007f2c8802be80):  JavaThread "main" [_thread_in_native, id=4712, stack(...)]
	curThreadRe = regexp.MustCompile(`(?m)^Current thread \(0x[0-9a-fA-F]+\):\s+(\S+)\s+"([^"]*)"\s+\[([^\]]+)\]`)
	frameLineRe = regexp.MustCompile(`^\s*([VCJjv])\s+(\[[^\]]+\]|\S+)\s*(.*)$`)
	sigInfoRe   = regexp.MustCompile(`(?m)^siginfo:\s*(.*)$`)
	stackFreeRe = regexp.MustCompile(`(?m)^Stack:\s*\[0x[0-9a-fA-F]+,0x[0-9a-fA-F]+\],\s*sp=0x[0-9a-fA-F]+,\s*free space=(\d+)k`)
)

// ParseThread fills CurrentThread, NativeFrames, JavaFrames, SigInfo and
// StackFreeKB from the THREAD section.
func ParseThread(r *model.CrashReport) error {
	body := r.Section("THREAD")

	if m := curThreadRe.FindStringSubmatch(body); m != nil {
		r.CurrentThread = model.Thread{
			Kind:  m[1],
			Name:  m[2],
			State: strings.TrimSpace(strings.Split(m[3], ",")[0]),
		}
		for _, part := range strings.Split(m[3], ",") {
			if strings.HasPrefix(strings.TrimSpace(part), "id=") {
				r.CurrentThread.ID = strings.TrimPrefix(strings.TrimSpace(part), "id=")
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
