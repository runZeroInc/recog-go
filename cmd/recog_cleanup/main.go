package main

import (
	"bufio"
	"fmt"
	"log"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	recogXml  = os.Getenv("RECOG_XML")
	reExtraWS = regexp.MustCompile("\\s+$")
)

func main() {
	log.SetFlags(0)
	if recogXml == "" {
		recogXml = "./recog/xml"
	}

	if err := filepath.Walk(recogXml, visit); err != nil {
		log.Fatal(err)
	}
}

func visit(path string, info os.FileInfo, err error) error {
	if err != nil {
		return err
	}

	if info.IsDir() || filepath.Ext(path) != ".xml" {
		return nil
	}

	return clean(path)
}

func clean(file string) error {
	f, err := os.Open(file)
	if err != nil {
		return fmt.Errorf("failed to read file contents: %s", err)
	}

	var lines []string
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Text()
		if reExtraWS.MatchString(line) {
			line = reExtraWS.ReplaceAllString(line, "")
		}
		// new line after every fingerprint
		if strings.Contains(line, "</fingerprint>") {
			line = strings.ReplaceAll(line, "</fingerprint>", "</fingerprint>\n")
		}
		// self-closing params
		if strings.Contains(line, "></param>") {
			line = strings.ReplaceAll(line, "></param>", "/>")
		}
		// cleanup comments
		if strings.Contains(line, "-->") {
			line = strings.ReplaceAll(line, "-->", "-->\n")
		}
		// skip empty lines
		if line == "" {
			continue
		}
		lines = append(lines, line)
	}

	if err := os.WriteFile(file, []byte(strings.Join(lines, "\n")), 0); err != nil {
		return fmt.Errorf("failed to write file contents: %s", err)
	}
	return nil
}
