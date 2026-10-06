package report

import (
	"encoding/json"
	"io"

	"crashscope/internal/classifier"
	"crashscope/internal/model"
	"crashscope/internal/version"
)

type jsonReport struct {
	Tool        string               `json:"tool"`
	Version     string               `json:"version"`
	File        string               `json:"file"`
	JDK         jsonJDK              `json:"jdk"`
	Signal      string               `json:"signal"`
	Thread      string               `json:"thread"`
	JVMArgs     string               `json:"jvm_args"`
	JavaCommand string               `json:"java_command"`
	Libraries   []string             `json:"libraries"`
	Verdicts    []classifier.Verdict `json:"verdicts"`
}

type jsonJDK struct {
	Vendor string `json:"vendor"`
	Major  int    `json:"major"`
	Raw    string `json:"raw"`
}

// RenderJSON writes the machine-readable report.
func RenderJSON(w io.Writer, r *model.CrashReport, vs []classifier.Verdict) error {
	// Normalize nil slices to empty ones so no field ever marshals as null
	// (JSON consumers iterate arrays, not nulls).
	norm := make([]classifier.Verdict, len(vs))
	for i, v := range vs {
		if v.Evidence == nil {
			v.Evidence = []string{}
		}
		if v.Fix == nil {
			v.Fix = []string{}
		}
		if v.Bugs == nil {
			v.Bugs = []classifier.Bug{}
		}
		norm[i] = v
	}
	doc := jsonReport{
		Tool:        "crashscope",
		Version:     version.Version,
		File:        r.Path,
		JDK:         jsonJDK{Vendor: r.JDKVendor, Major: r.JDKMajor, Raw: r.JVMVersion},
		Signal:      r.Signal,
		Thread:      r.CurrentThread.Name,
		JVMArgs:     r.JVMArgs,
		JavaCommand: r.JavaCommand,
		Libraries:   r.Libraries,
		Verdicts:    norm,
	}
	if doc.Libraries == nil {
		doc.Libraries = []string{}
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(doc)
}
