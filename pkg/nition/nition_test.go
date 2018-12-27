package nition

import (
	"testing"
)

func TestLoad(t *testing.T) {
	fset, err := LoadFingerprints()
	if err != nil {
		t.Errorf("LoadFingerprints() failed: %s", err)
	}
	if len(fset) == 0 {
		t.Errorf("LoadFingerprints() returned an empty set")
	}
}

func TestExamples(t *testing.T) {
	fset, err := LoadFingerprints()
	if err != nil {
		t.Errorf("LoadFingerprints() failed")
	}
	if len(fset) == 0 {
		t.Errorf("LoadFingerprints() returned an empty set")
	}
	for name, fdb := range fset {
		err := fdb.VerifyExamples()
		if err != nil {
			t.Errorf("VerifyExamples() failed for %s: %s", name, err)
		}
	}
}
