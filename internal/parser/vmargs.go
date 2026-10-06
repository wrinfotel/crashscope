package parser

import (
	"regexp"
	"strings"

	"crashscope/internal/model"
)

var (
	jvmArgsRe     = regexp.MustCompile(`(?m)^jvm_args:\s*(.*)$`)
	javaCommandRe = regexp.MustCompile(`(?m)^java_command:\s*(.*)$`)
)

// ParseVMArgs fills JVMArgs, JavaCommand and Events.
func ParseVMArgs(r *model.CrashReport) error {
	if m := jvmArgsRe.FindStringSubmatch(r.Section("VMARGS")); m != nil {
		r.JVMArgs = strings.TrimSpace(m[1])
	}
	if m := javaCommandRe.FindStringSubmatch(r.Section("VMARGS")); m != nil {
		r.JavaCommand = strings.TrimSpace(m[1])
	}
	for _, ln := range strings.Split(r.Section("EVENTS"), "\n") {
		ln = strings.TrimSpace(ln)
		if ln != "" {
			r.Events = append(r.Events, ln)
		}
	}
	return nil
}
