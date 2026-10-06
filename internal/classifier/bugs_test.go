package classifier

import (
	"testing"

	"crashscope/internal/model"
)

func TestBugMatcher(t *testing.T) {
	defs := []bugDef{{
		ID:           "JDK-TEST",
		JDKMajor:     []int{17},
		VersionRegex: `17\.0\.4`,
		Library:      "libsqlitejdbc.so",
		SymbolRegex:  `sqlite3_prepare`,
		URL:          "https://example.invalid/JDK-TEST",
		Summary:      "test entry",
		Fix:          "test fix",
	}}
	r := reportWithProblemFrame(17, "17.0.4.1+1", "C", "[libsqlitejdbc.so+0x6a2b]", "sqlite3_prepare_v2+0x3b")
	hits := matchBugs(defs, r)
	if len(hits) != 1 || hits[0].ID != "JDK-TEST" {
		t.Fatalf("hits = %+v", hits)
	}

	r2 := reportWithProblemFrame(21, "21.0.1+8", "C", "[libsqlitejdbc.so+0x6a2b]", "sqlite3_prepare_v2+0x3b")
	if hits := matchBugs(defs, r2); len(hits) != 0 {
		t.Fatalf("wrong-major hits = %+v", hits)
	}
}

// TestRealBugEntriesMatch proves every entry embedded from bugs.json matches a
// synthetic report carrying the real JDK version and crash-symbol strings from
// its JBS issue. Fixtures use the actual strings quoted on the issue pages
// (full "# Java VM:" line shape, real problematic-frame locations/symbols).
func TestRealBugEntriesMatch(t *testing.T) {
	defs := loadBugs()
	if len(defs) == 0 {
		t.Skip("bugs.json is empty: no real entries to verify")
	}
	fixtures := map[string]struct {
		major  int
		vmLine string
		loc    string
		symbol string
	}{
		"JDK-8303737": { // Elasticsearch CI crash, product build 21.0.1+12
			major:  21,
			vmLine: "Java HotSpot(TM) 64-Bit Server VM (21.0.1+12-LTS-29, mixed mode, sharing, tiered, compressed oops, g1 gc, linux-amd64)",
			loc:    "libjvm.so+0xb93f0e",
			symbol: "PhaseIdealLoop::build_loop_late_post_work(Node*, bool)+0xce",
		},
		"JDK-8356324": { // -Xshare:dump crash, affected release 21.0.5
			major:  21,
			vmLine: "Java HotSpot(TM) 64-Bit Server VM (21.0.5+7, mixed mode, sharing, tiered, compressed oops, g1 gc, linux-amd64)",
			loc:    "libjvm.so+0x1e2",
			symbol: "ClassListParser::resolve_indy_impl+0x1e2",
		},
		"JDK-8361117": { // ECJ-compiled bytecode crash on 17.0.15
			major:  17,
			vmLine: "Java HotSpot(TM) 64-Bit Server VM (17.0.15+9-LTS-241, mixed mode, sharing, tiered, compressed oops, g1 gc, linux-amd64)",
			loc:    "libjvm.so+0xbbe648",
			symbol: "LShiftLNode::Ideal(PhaseGVN*, bool)+0x378",
		},
		"JDK-8374463": { // Netty retryRelease0 C2 crash on 25.0.1
			major:  25,
			vmLine: "OpenJDK 64-Bit Server VM Zulu25.30+17-CA (25.0.1+8-LTS, mixed mode, sharing)",
			loc:    "libjvm.so+0x71dcce",
			symbol: "Compile::final_graph_reshaping_walk(Node_Stack&, Node*, Final_Reshape_Counts&, Unique_Node_List&)+0x32e",
		},
	}
	for _, d := range defs {
		fx, ok := fixtures[d.ID]
		if !ok {
			t.Errorf("entry %s has no real-string fixture: add one to TestRealBugEntriesMatch", d.ID)
			continue
		}
		r := reportWithProblemFrame(fx.major, fx.vmLine, "V", "["+fx.loc+"]", fx.symbol)
		hits := matchBugs(defs, r)
		found := false
		for _, h := range hits {
			if h.ID == d.ID {
				found = true
			}
		}
		if !found {
			t.Errorf("entry %s does not match its real version/symbol: hits = %+v", d.ID, hits)
		}
	}

	// Fixed releases must no longer match their entry.
	fixed := map[string]*model.CrashReport{
		"JDK-8303737": reportWithProblemFrame(21, "Java HotSpot(TM) 64-Bit Server VM (21.0.2+13-58, mixed mode, sharing)", "V", "[libjvm.so+0xb93f0e]", "PhaseIdealLoop::build_loop_late_post_work(Node*, bool)+0xce"),
		"JDK-8356324": reportWithProblemFrame(21, "Java HotSpot(TM) 64-Bit Server VM (21.0.9+7-LTS-292, mixed mode, sharing)", "V", "[libjvm.so+0x1e2]", "ClassListParser::resolve_indy_impl+0x1e2"),
		"JDK-8361117": reportWithProblemFrame(17, "Java HotSpot(TM) 64-Bit Server VM (17.0.19+7-LTS-101, mixed mode, sharing)", "V", "[libjvm.so+0xbbe648]", "LShiftLNode::Ideal(PhaseGVN*, bool)+0x378"),
		"JDK-8374463": reportWithProblemFrame(25, "OpenJDK 64-Bit Server VM (25.0.2+9, mixed mode, sharing)", "V", "[libjvm.so+0x71dcce]", "Compile::final_graph_reshaping_walk(Node_Stack&, Node*, Final_Reshape_Counts&, Unique_Node_List&)+0x32e"),
	}
	for _, d := range defs {
		r, ok := fixed[d.ID]
		if !ok {
			continue
		}
		if hits := matchBugs(defs, r); len(hits) != 0 {
			t.Errorf("entry %s must not match the fixed release: hits = %+v", d.ID, hits)
		}
	}
}

// TestClassifyIntegratesBugs checks the Classify tail: bug hits are surfaced
// through the verdicts (dedicated "known-jvm-bug" verdict when no rule fired,
// Bugs attached to every verdict otherwise).
func TestClassifyIntegratesBugs(t *testing.T) {
	r := reportWithProblemFrame(17,
		"Java HotSpot(TM) 64-Bit Server VM (17.0.15+9-LTS-241, mixed mode, sharing, tiered, compressed oops, g1 gc, linux-amd64)",
		"V", "[libjvm.so+0xbbe648]", "LShiftLNode::Ideal(PhaseGVN*, bool)+0x378")
	verdicts := Classify(r)
	if len(verdicts) == 0 {
		t.Fatal("Classify returned no verdicts")
	}
	realIDs := map[string]bool{
		"JDK-8303737": true, "JDK-8356324": true, "JDK-8361117": true, "JDK-8374463": true,
	}
	anyBug := false
	for _, v := range verdicts {
		if len(v.Bugs) == 0 {
			t.Errorf("verdict %s has no Bugs attached: %+v", v.ID, v)
			continue
		}
		anyBug = true
		if !realIDs[v.Bugs[0].ID] {
			t.Errorf("verdict %s: Bugs[0].ID %q is not a real entry id", v.ID, v.Bugs[0].ID)
		}
	}
	if !anyBug {
		t.Fatal("no verdict carries bug hits")
	}
	foundJDK8361117 := false
	for _, v := range verdicts {
		for _, b := range v.Bugs {
			if b.ID == "JDK-8361117" {
				foundJDK8361117 = true
			}
		}
	}
	if !foundJDK8361117 {
		t.Error("JDK-8361117 not attached to any verdict")
	}
}

// TestClassifyKnownBugFallback covers the len(out)==0 branch of the Classify
// tail: no rule fires (ProblemFrame type "J" keys no rule and the report
// carries no text), but a real bug def matches — so exactly the dedicated
// "known-jvm-bug" verdict (medium) appears instead of the "unknown" fallback.
func TestClassifyKnownBugFallback(t *testing.T) {
	r := reportWithProblemFrame(17,
		"Java HotSpot(TM) 64-Bit Server VM (17.0.15+9-LTS-241, mixed mode, sharing, tiered, compressed oops, g1 gc, linux-amd64)",
		"J", "libjvm.so+0x123", "LShiftLNode::Ideal(PhaseGVN*, bool)+0x378")
	verdicts := Classify(r)
	if len(verdicts) != 1 {
		t.Fatalf("verdicts = %+v, want exactly the known-jvm-bug verdict", verdicts)
	}
	v := verdicts[0]
	if v.ID != "known-jvm-bug" {
		t.Fatalf("verdict ID = %s, want known-jvm-bug", v.ID)
	}
	if v.Confidence != "medium" {
		t.Errorf("Confidence = %q, want medium", v.Confidence)
	}
	if len(v.Bugs) == 0 || v.Bugs[0].ID != "JDK-8361117" {
		t.Errorf("Bugs = %+v, want JDK-8361117 first", v.Bugs)
	}
	if v.ID == "unknown" {
		t.Error("unknown fallback verdict must not appear when a bug matched")
	}
}
