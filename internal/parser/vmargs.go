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
	// Real hs_err logs (JDK 7-17) carry jvm_args:/java_command: as plain
	// blocks inside the P R O C E S S section, with no "V M  A R G S"
	// header — fall back to the PROCESS body when the section is absent.
	src := r.Section("VMARGS")
	if src == "" {
		src = r.Section("PROCESS")
	}
	if m := jvmArgsRe.FindStringSubmatch(src); m != nil {
		r.JVMArgs = strings.TrimSpace(m[1])
	}
	if m := javaCommandRe.FindStringSubmatch(src); m != nil {
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
