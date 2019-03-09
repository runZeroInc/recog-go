package nition

//go:generate git submodule update
//go:generate go run vfsgen-recog/main.go

import (
	"fmt"
	"io/ioutil"
	"log"
	"strings"

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

	rootfs, err := Assets.Open("/")
	if err != nil {
		return res, err
	}
	defer rootfs.Close()

	files, err := rootfs.Readdir(65535)
	if err != nil {
		return res, err
	}

	for _, f := range files {

		if !strings.Contains(f.Name(), ".xml") {
			continue
		}

		fd, err := Assets.Open(f.Name())
		if err != nil {
			return res, err
		}

		xmlData, err := ioutil.ReadAll(fd)
		if err != nil {
			log.Fatal(err)
		}
		fd.Close()

		fdb, err := recog.LoadFingerprintDB(f.Name(), xmlData)
		if err != nil {
			log.Fatal(err)
		}
		res.Databases[f.Name()] = &fdb
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
