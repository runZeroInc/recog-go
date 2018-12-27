package nition

//go:generate git submodule update
//go:generate go get github.com/gobuffalo/packr/packr
//go:generate packr

import (
	"fmt"
	"log"

	"github.com/gobuffalo/packr"
	recog "github.com/hdm/recog-go"
)

// FingerprintSet is a collection of loaded Recog fingerprint databases
type FingerprintSet struct {
	Databases map[string]*recog.FingerprintDB
}

// NewFingerprintSet returns an allocated FingerprintSet structure
func NewFingerprintSet() *FingerprintSet {
	fs := &FingerprintSet{}
	fs.Databases = make(map[string]*recog.FingerprintDB)
	return fs
}

// MatchFirst matches data to a given fingerprint database
func (fs *FingerprintSet) MatchFirst(name string, data string) *recog.FingerprintMatch {
	nomatch := &recog.FingerprintMatch{Matched: false}
	fdb, ok := fs.Databases[name]
	if !ok {
		nomatch.Errors = append(nomatch.Errors, fmt.Errorf("database %s is missing", name))
		return nomatch
	}
	return fdb.MatchFirst(data)
}

// MatchAll matches data to a given fingerprint database
func (fs *FingerprintSet) MatchAll(name string, data string) []*recog.FingerprintMatch {
	nomatch := &recog.FingerprintMatch{Matched: false}
	fdb, ok := fs.Databases[name]
	if !ok {
		nomatch.Errors = append(nomatch.Errors, fmt.Errorf("database %s is missing", name))
		return []*recog.FingerprintMatch{nomatch}
	}
	return fdb.MatchAll(data)
}

// LoadFingerprints parses embedded Recog XML databases, returning a map
func LoadFingerprints() (*FingerprintSet, error) {
	res := NewFingerprintSet()

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
		res.Databases[name] = &fdb
	}

	return res, nil
}

// MustLoadFingerprints loads the built-in fingerprints, panicing otherwise
func MustLoadFingerprints() *FingerprintSet {
	fset, err := LoadFingerprints()
	if err != nil {
		panic(err)
	}
	return fset
}
