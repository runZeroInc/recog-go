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
		return
	}
	if len(fset) == 0 {
		t.Errorf("LoadFingerprints() returned an empty set")
		return
	}
	for name, fdb := range fset {
		err := fdb.VerifyExamples()
		if err != nil {
			t.Errorf("VerifyExamples() failed for %s: %s", name, err)
		}
	}
}

func TestPJL(t *testing.T) {
	fset, err := LoadFingerprints()
	if err != nil {
		t.Errorf("LoadFingerprints() failed")
		return
	}
	if len(fset) == 0 {
		t.Errorf("LoadFingerprints() returned an empty set")
		return
	}

	pjl, ok := fset["hp_pjl_id.xml"]
	if !ok {
		t.Errorf("Missing hp_pjl_id.xml fingerprints")
		return
	}

	m := pjl.MatchFirst("Xerox ColorQube 8570DT")
	if m == nil {
		t.Errorf("Failed to match 'Xerox ColorQube 8570DT'")
		return
	}

	if m.Attributes["os.product"] != "8570DT" || m.Attributes["os.vendor"] != "Xerox" {
		t.Errorf("Failed to match 'Xerox ColorQube 8570DT' expected product or vendor")
	}
}
