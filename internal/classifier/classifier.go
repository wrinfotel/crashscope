package classifier

import (
	"sort"

	"crashscope/internal/model"
)

// Verdict is one diagnosed cause with actionable fixes.
type Verdict struct {
	ID         string // stable rule id, e.g. "sigsegv-jni"
	Title      string // one-line human summary
	Confidence string // "high" | "medium" | "low"
	Summary    string
	Fix        []string
	Evidence   []string // quoted lines from the log
	Bugs       []Bug    // known-JVM-bug hits matching this crash
}

var confidenceRank = map[string]int{"high": 3, "medium": 2, "low": 1}

// Classify applies all rules and returns verdicts sorted by confidence.
// Never returns an empty slice: an unmatched crash yields the "unknown" verdict.
func Classify(r *model.CrashReport) []Verdict {
	var out []Verdict
	for _, rule := range rules {
		if v, ok := rule(r); ok {
			out = append(out, *v)
		}
	}
	if hits := matchBugs(loadBugs(), r); len(hits) > 0 {
		if len(out) == 0 {
			out = append(out, Verdict{
				ID:         "known-jvm-bug",
				Title:      "Matches a known JVM bug",
				Confidence: "medium",
				Summary:    hits[0].Summary,
				Fix:        []string{hits[0].Fix},
				Bugs:       hits,
			})
		} else {
			for i := range out {
				out[i].Bugs = hits
			}
		}
	}
	sort.SliceStable(out, func(i, j int) bool {
		return confidenceRank[out[i].Confidence] > confidenceRank[out[j].Confidence]
	})
	if len(out) == 0 {
		out = append(out, fallbackVerdict(r))
	}
	return out
}

func fallbackVerdict(r *model.CrashReport) Verdict {
	return Verdict{
		ID:         "unknown",
		Title:      "Unrecognized crash pattern",
		Confidence: "low",
		Summary:    "The log parsed cleanly but no rule matched. Signal " + r.Signal + ".",
		Fix: []string{
			"Update to the latest CPU release of your JDK line — most JVM crashes are already-fixed bugs.",
			"Re-run with the same workload after the update; if it reproduces, file an issue with this hs_err attached.",
			"Manual starting points: the 'Problematic frame' entry and the Events section tail.",
		},
	}
}
