package main

import (
	"bufio"
	"compress/gzip"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"strings"
)

func visit(files *[]string) filepath.WalkFunc {
	return func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Fatal(err)
		}

		if info.IsDir() || filepath.Ext(path) != ".gz" {
			return nil
		}

		*files = append(*files, path)
		return nil
	}
}

func main() {
	var files []string
	if len(os.Args) < 2 {
		log.Fatalf("missing: certificates directory")
	}

	err := filepath.Walk(os.Args[1], visit(&files))
	if err != nil {
		log.Fatal(err)
	}

	// Open each certificate file and attach a gzip reader
	for _, file := range files {
		fd, err := os.Open(file)
		if err != nil {
			log.Fatalf("could not open file: %s %s", file, err)
		}
		defer fd.Close()

		gz, err := gzip.NewReader(fd)
		if err != nil {
			log.Fatalf("could not gunzip file: %s %s", file, err)
		}
		defer gz.Close()

		// Process the file
		process(gz)
	}
}

func process(gz *gzip.Reader) {
	scanner := bufio.NewScanner(gz)

	// Use a 8mb line length buffer (probably overkill)
	buf := make([]byte, 0, 1024*1024*8)
	scanner.Buffer(buf, 1024*1024*8)

	for scanner.Scan() {
		data := scanner.Text()
		bits := strings.Split(data, ",")
		if len(bits) != 2 {
			log.Printf("bad line: %s", data)
			continue
		}

		blob, err := base64.StdEncoding.DecodeString(bits[1])
		if err != nil {
			log.Printf("bad base64: %s (%s)", err, data)
			continue
		}

		// TODO: Use lower-level implementation to extract subject/issuer even when there are
		//       validation errors (cannot parse IP address, invalid domain, etc)
		cert, err := x509.ParseCertificate(blob)
		if err != nil {
			log.Printf("invalid cert: %s (%s)", err, hex.EncodeToString(blob))
			continue
		}

		fmt.Printf("%s\n", cert.Issuer)
		// log.Printf("issuer: %s", cert.Subject)

	}
	if err := scanner.Err(); err != nil {
		fmt.Fprintln(os.Stderr, "reading standard input:", err)
	}
}
