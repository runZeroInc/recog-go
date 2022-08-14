package main

import (
	"os"
	"path/filepath"

	log "github.com/sirupsen/logrus"

	recog "github.com/runZeroInc/recog-go"
)

func visit(files *[]string) filepath.WalkFunc {
	return func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Fatal(err)
		}

		if info.IsDir() || filepath.Ext(path) != ".xml" {
			return nil
		}

		*files = append(*files, path)
		return nil
	}
}

func main() {
	var files []string
	if len(os.Args) < 2 {
		log.Fatalf("missing: recog xml directory")
	}

	err := filepath.Walk(os.Args[1], visit(&files))
	if err != nil {
		log.Fatal(err)
	}

	var hasErr error
	// Load each database and verify the fingerprints against their examples
	for _, file := range files {
		fdb, err := recog.LoadFingerprintDBFromFile(file)
		if err != nil {
			log.Fatalf("error loading fingerprints from %s: %s", file, err)
		}
		log.Printf("loaded %d fingerprints from %s", len(fdb.Fingerprints), file)
		fpath := file[:len(file)-len(filepath.Ext(file))]
		err = fdb.VerifyExamples(fpath)
		if err != nil {
			log.Errorf("error verifying examples in %s: %s", file, err)
			hasErr = err
		}
	}

	if hasErr != nil {
		os.Exit(1)
	}

	os.Exit(0)
}
