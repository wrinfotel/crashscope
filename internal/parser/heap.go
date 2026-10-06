package parser

import (
	"regexp"
	"strings"

	"crashscope/internal/model"
)

var gcPatterns = []struct {
	re   *regexp.Regexp
	name string
}{
	// (?i): the JVM version line reports e.g. "g1 gc" in lower case.
	{regexp.MustCompile(`(?i)Garbage-First|\bG1\b`), "G1"},
	{regexp.MustCompile(`(?i)ZHeap|ZGarbageCollector|\bZGC\b|\bz gc\b`), "ZGC"},
	{regexp.MustCompile(`(?i)Shenandoah`), "Shenandoah"},
	{regexp.MustCompile(`(?i)PSYoungGen|ParOldGen|\bParallel\b`), "Parallel"},
	{regexp.MustCompile(`(?i)SerialGC|DefNew`), "Serial"},
}

// ParseHeap fills GCName and the OOMInEvents marker.
func ParseHeap(r *model.CrashReport) error {
	hay := r.Section("HEAP") + " " + r.JVMArgs + " " + r.JVMVersion
	for _, p := range gcPatterns {
		if p.re.MatchString(hay) {
			r.GCName = p.name
			break
		}
	}
	all := strings.Join(r.Events, " ") + " " + strings.Join(r.Messages, " ")
	r.OOMInEvents = strings.Contains(all, "OutOfMemory") ||
		strings.Contains(all, "out of memory") ||
		strings.Contains(all, "out of swap space")
	return nil
}
