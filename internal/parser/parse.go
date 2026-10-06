package parser

import "crashscope/internal/model"

// Parse runs the full pipeline: split + header + thread + vmargs + memmap + heap.
// It only fails on input that is not an hs_err log.
func Parse(path string, raw []byte) (*model.CrashReport, error) {
	r, err := Split(path, raw)
	if err != nil {
		return nil, err
	}
	for _, step := range []func(*model.CrashReport) error{
		ParseHeader, ParseThread, ParseVMArgs, ParseMemMap, ParseHeap,
	} {
		if err := step(r); err != nil {
			return nil, err
		}
	}
	return r, nil
}
