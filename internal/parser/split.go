package parser

import (
	"fmt"
	"regexp"
	"strings"

	"crashscope/internal/model"
)

// Matches "---------------  S U M M A R Y ------------" style header lines.
// Lines of bare dashes do not match (title must start with a non-dash).
var sectionHeaderRe = regexp.MustCompile(`(?m)^-{5,}\s*([^-\s][^-]*?)\s*-{5,}[ \t]*$`)

// despace turns "V M  O P E R A T I O N S" into "VMOPERATIONS".
func despace(s string) string {
	return strings.ToUpper(strings.Join(strings.Fields(s), ""))
}

// Split cuts an hs_err file into the prologue and titled sections.
// It returns an error for input that is not an hs_err log at all.
func Split(path string, raw []byte) (*model.CrashReport, error) {
	text := strings.ReplaceAll(string(raw), "\r\n", "\n")

	type sec struct{ lineStart, lineEnd int }
	var secs []sec
	var titles []string
	for _, m := range sectionHeaderRe.FindAllStringSubmatchIndex(text, -1) {
		title := strings.TrimSpace(text[m[2]:m[3]])
		if title == "" {
			continue
		}
		secs = append(secs, sec{m[0], m[1]})
		titles = append(titles, title)
	}

	prologueEnd := len(text)
	if len(secs) > 0 {
		prologueEnd = secs[0].lineStart
	}
	prologue := text[:prologueEnd]

	// The prologue "#" block (fatal-error or OOM message) is present in every
	// real hs_err log; it is the format's fingerprint. Requiring it even when
	// section headers exist keeps arbitrary text chopped into "-----" sections
	// from masquerading as a crash log (which would misreport exit 1 as
	// "parsed but unrecognized").
	if !strings.Contains(prologue, "# A fatal error has been detected") &&
		!strings.Contains(prologue, "insufficient memory for the Java Runtime Environment") {
		return nil, fmt.Errorf("%s: not an hs_err_pid log", path)
	}

	r := &model.CrashReport{
		Path:        path,
		Prologue:    prologue,
		Sections:    map[string]string{},
		StackFreeKB: -1,
	}
	for i, s := range secs {
		end := len(text)
		if i+1 < len(secs) {
			end = secs[i+1].lineStart
		}
		body := strings.TrimSpace(text[s.lineEnd:end])
		key := despace(titles[i])
		r.Sections[key] = body
		r.SectionOrder = append(r.SectionOrder, key)
	}
	return r, nil
}
