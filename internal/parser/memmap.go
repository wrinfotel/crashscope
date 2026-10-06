package parser

import (
	"regexp"
	"strings"

	"crashscope/internal/model"
)

// 7f2c6b500000-7f2c6b600000 r--p 00000000 fd:01 1048577     /opt/app/lib/libsqlitejdbc.so
var mapLineRe = regexp.MustCompile(`^([0-9a-fA-F]{8,16})-([0-9a-fA-F]{8,16})\s+(\S{4})\s+\S+\s+\S+\s+\S+\s+(\S.*)$`)

// Windows module list: 0x00007ffa9a000000  18944K  C:\...\jvm.dll
var winMapLineRe = regexp.MustCompile(`^0x[0-9a-fA-F]{8,16}\s+\d+K?\s+(\S.*)$`)

// ParseMemMap fills Modules and the unique native Libraries list.
// Unknown line shapes are skipped, not errors.
func ParseMemMap(r *model.CrashReport) error {
	seen := map[string]bool{}
	for _, ln := range strings.Split(r.Section("MAP"), "\n") {
		e, ok := matchMapLine(strings.TrimSpace(ln))
		if !ok {
			continue
		}
		r.Modules = append(r.Modules, e)

		lower := strings.ToLower(e.Path)
		native := strings.HasSuffix(lower, ".so") || strings.HasSuffix(lower, ".dll") ||
			strings.HasSuffix(lower, ".dylib") || strings.HasSuffix(lower, ".jnilib")
		if native && !seen[e.Path] {
			seen[e.Path] = true
			r.Libraries = append(r.Libraries, e.Path)
		}
	}
	return nil
}

// matchMapLine parses one MAP line: ELF /proc/maps style first, then the
// Windows module list form (no start-end range, no permissions).
func matchMapLine(ln string) (model.MapEntry, bool) {
	if m := mapLineRe.FindStringSubmatch(ln); m != nil {
		return model.MapEntry{Start: m[1], End: m[2], Perms: m[3], Path: strings.TrimSpace(m[4])}, true
	}
	if m := winMapLineRe.FindStringSubmatch(ln); m != nil {
		return model.MapEntry{Path: strings.TrimSpace(m[1])}, true
	}
	return model.MapEntry{}, false
}
