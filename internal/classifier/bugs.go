package classifier

import (
	_ "embed"
	"encoding/json"
	"regexp"
	"strings"

	"crashscope/internal/model"
)

// Bug is a known-bug hit surfaced in the report.
type Bug struct {
	ID      string `json:"id"`
	URL     string `json:"url"`
	Summary string `json:"summary"`
	Fix     string `json:"fix"`
}

type bugDef struct {
	ID           string `json:"id"`
	JDKMajor     []int  `json:"jdk_major"` // empty = any
	VersionRegex string `json:"version_regex"`
	Library      string `json:"library"`      // substring of the frame location; empty = any
	SymbolRegex  string `json:"symbol_regex"` // matched against the problematic frame symbol
	URL          string `json:"url"`
	Summary      string `json:"summary"`
	Fix          string `json:"fix"`
}

//go:embed bugs.json
var bugsJSON []byte

func loadBugs() []bugDef {
	var defs []bugDef
	if err := json.Unmarshal(bugsJSON, &defs); err != nil {
		return nil // a broken database must never break analysis
	}
	return defs
}

// matchBugs returns known-bug entries matching the report.
func matchBugs(defs []bugDef, r *model.CrashReport) []Bug {
	var out []Bug
	for _, d := range defs {
		if len(d.JDKMajor) > 0 {
			ok := false
			for _, mj := range d.JDKMajor {
				if r.JDKMajor == mj {
					ok = true
				}
			}
			if !ok {
				continue
			}
		}
		if d.VersionRegex != "" {
			re, err := regexp.Compile(d.VersionRegex)
			if err != nil || !re.MatchString(r.JVMVersion) {
				continue
			}
		}
		loc := strings.Trim(r.ProblemFrame.Location, "[]")
		if d.Library != "" && !strings.Contains(loc, d.Library) &&
			!strings.Contains(strings.Join(r.Libraries, " "), d.Library) {
			continue
		}
		if d.SymbolRegex != "" {
			re, err := regexp.Compile(d.SymbolRegex)
			if err != nil || !re.MatchString(r.ProblemFrame.Symbol) {
				continue
			}
		}
		out = append(out, Bug{ID: d.ID, URL: d.URL, Summary: d.Summary, Fix: d.Fix})
	}
	return out
}

// reportWithProblemFrame builds a minimal report for tests.
func reportWithProblemFrame(major int, version, ftype, loc, symbol string) *model.CrashReport {
	return &model.CrashReport{
		JDKMajor:     major,
		JVMVersion:   version,
		ProblemFrame: model.Frame{Type: ftype, Location: loc, Symbol: symbol},
	}
}
