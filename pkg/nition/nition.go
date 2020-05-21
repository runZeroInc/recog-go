package nition

//go:generate git submodule update
//go:generate go run vfsgen-recog/main.go

import (
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"

	log "github.com/sirupsen/logrus"

	recog "github.com/RumbleDiscovery/recog-go"
)

// FingerprintSet is a collection of loaded Recog fingerprint databases
type FingerprintSet struct {
	Databases map[string]*recog.FingerprintDB
	Logger    *log.Logger
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

// LoadFingerprints parses the embedded Recog XML databases, returning a FingerprintSet
func (fs *FingerprintSet) LoadFingerprints() error {
	return fs.LoadFingerprintsFromFS(Assets)
}

// LoadFingerprintsDir parses Recog XML files from a local directory, returning a FingerprintSet
func (fs *FingerprintSet) LoadFingerprintsDir(dname string) error {
	return fs.LoadFingerprintsFromFS(http.Dir(dname))
}

// LoadFingerprintsFromFS parses an embedded Recog XML database, returning a FingerprintSet
func (fs *FingerprintSet) LoadFingerprintsFromFS(efs http.FileSystem) error {
	rootfs, err := efs.Open("/")
	if err != nil {
		return err
	}
	defer rootfs.Close()

	files, err := rootfs.Readdir(65535)
	if err != nil {
		return err
	}

	for _, f := range files {

		if !strings.Contains(f.Name(), ".xml") {
			continue
		}

		fd, err := efs.Open(f.Name())
		if err != nil {
			return err
		}

		xmlData, err := ioutil.ReadAll(fd)
		if err != nil {
			fd.Close()
			return err
		}
		fd.Close()

		fdb, err := recog.LoadFingerprintDB(f.Name(), xmlData)
		if err != nil {
			return err
		}

		fdb.Logger = fs.Logger

		// Create an alias for the file name
		fs.Databases[f.Name()] = &fdb

		// Create an alias for the "matches" attribute
		fs.Databases[fdb.Matches] = &fdb
	}

	return nil
}

// LoadFingerprints parses embedded Recog XML databases, returning a FingerprintSet
func LoadFingerprints() (*FingerprintSet, error) {
	res := NewFingerprintSet()
	return res, res.LoadFingerprints()
}

// LoadFingerprintsDir parses Recog XML files from a local directory, returning a FingerprintSet
func LoadFingerprintsDir(dname string) (*FingerprintSet, error) {
	res := NewFingerprintSet()
	return res, res.LoadFingerprintsDir(dname)
}

// MustLoadFingerprints loads the built-in fingerprints, panicing otherwise
func MustLoadFingerprints() *FingerprintSet {
	fset, err := LoadFingerprints()
	if err != nil {
		panic(err)
	}
	return fset
}
