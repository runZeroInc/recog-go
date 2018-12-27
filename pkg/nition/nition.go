package nition

//go:generate git submodule update
//go:generate go get github.com/gobuffalo/packr/packr
//go:generate packr

import (
	"log"

	"github.com/gobuffalo/packr"
	recog "github.com/hdm/recog-go"
)

// LoadFingerprints parses embedded Recog XML databases, returning a map
func LoadFingerprints() (map[string]recog.FingerprintDB, error) {
	res := make(map[string]recog.FingerprintDB)

	// set up a new box by giving it a (relative) path to a folder on disk
	box := packr.NewBox("./recog/xml/")

	for _, name := range box.List() {
		xmlData, err := box.Find(name)
		if err != nil {
			log.Fatal(err)
		}

		fdb, err := recog.LoadFingerprintDB(name, xmlData)
		if err != nil {
			log.Fatal(err)
		}
		res[name] = fdb
	}

	return res, nil
}

// MustLoadFingerprints loads the built-in fingerprints, panicing otherwise
func MustLoadFingerprints() map[string]recog.FingerprintDB {
	fset, err := LoadFingerprints()
	if err != nil {
		panic(err)
	}
	return fset
}
