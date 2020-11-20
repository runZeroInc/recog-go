package recog

import (
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"regexp"
	"regexp/syntax"
	"strconv"
	"strings"

	log "github.com/sirupsen/logrus"
)

// FingerprintDescription contains a human-readable description of this fingerprint entry
type FingerprintDescription struct {
	Text string `xml:",chardata" json:"text,omitempty"`
}

// FingerprintParam represents a matched parameter
type FingerprintParam struct {
	Position string `xml:"pos,attr"  json:"pos,omitempty"`
	Name     string `xml:"name,attr"  json:"name,omitempty"`
	Value    string `xml:"value,attr"  json:"value,omitempty"`
}

// FingerprintExample contains an example match string
type FingerprintExample struct {
	Text string `xml:",chardata" json:"text,omitempty"`
	// Values include _encoding (base64) and parsed component versions (service.version, etc)
	Values       []xml.Attr        `xml:",any,attr" json:"attrs,omitempty"`
	AttributeMap map[string]string `xml:"-" json:"-"`
}

// Fingerprint represents a unique Recog fingerprint definition
type Fingerprint struct {
	Pattern         string                  `xml:"pattern,attr" json:"pattern,omitempty"`
	Flags           string                  `xml:"flags,attr"  json:"flags,omitempty"`
	Description     *FingerprintDescription `xml:"description,omitempty" json:"description,omitempty"`
	Examples        []*FingerprintExample   `xml:"example,omitempty" json:"example,omitempty"`
	Params          []*FingerprintParam     `xml:"param,omitempty" json:"param,omitempty"`
	Certainty       string                  `xml:"certainty,attr" json:"certainty,omitempty"`
	PatternCompiled *regexp.Regexp          `xml:"-" json:"-"`
}

var flagsPattern = regexp.MustCompile("[|,]")

// Normalize processes a fingerprint to make it easier to use
func (fp *Fingerprint) Normalize() error {

	// Recog uses PCRE so set the Perl compatibility flag here
	flags := syntax.PerlX
	flagStrings := flagsPattern.Split(fp.Flags, -1)

	for fi := range flagStrings {
		switch flagStrings[fi] {
		case "REG_ICASE", "IGNORECASE":
			flags |= syntax.FoldCase
		case "REG_DOT_NEWLINE", "REG_MULTILINE", "REG_LINE_ANY_CRLF":
			flags |= syntax.MatchNL
		}
	}

	// Workaround for recog #209 (use of \u0000 in telnet_banners.xml)
	fp.Pattern = strings.Replace(fp.Pattern, "\\u0000", "\\x00", -1)

	// Parse the regular expression
	parsed, err := syntax.Parse(fp.Pattern, flags)
	if err != nil {
		return fmt.Errorf("bad regexp syntax [%s]: %s", fp.Pattern, err)
	}

	// Compile the parsed syntax tree
	fp.PatternCompiled, err = regexp.Compile(parsed.String())
	if err != nil {
		return fmt.Errorf("bad regexp[%s]: %s", fp.Pattern, err)
	}
	for _, ex := range fp.Examples {
		ex.AttributeMap = make(map[string]string)
		for _, attr := range ex.Values {
			ex.AttributeMap[attr.Name.Local] = attr.Value
		}
	}
	return nil
}

// Pattern to substitute Values in the param values
var varSubPattern = regexp.MustCompile(`\{[a-zA-Z0-9._\-]+\}`)

// Match a fingerprint against a string
func (fp *Fingerprint) Match(data string) *FingerprintMatch {
	res := &FingerprintMatch{Matched: false}

	matches := fp.PatternCompiled.FindStringSubmatch(data)
	if len(matches) == 0 {
		return res
	}

	res.Matched = true
	res.Values = make(map[string]string)

	// Set the certainty if available
	if fp.Certainty != "" {
		res.Values["fp.certainty"] = fp.Certainty
	}

	// Extract match parameters (first pass)
	for _, p := range fp.Params {
		if p.Position == "0" {
			res.Values[p.Name] = p.Value
			continue
		}
		val, err := strconv.Atoi(p.Position)
		if err != nil {
			res.Errors = append(res.Errors, fmt.Errorf("param index %s is invalid: %s", p.Position, err))
			continue
		}
		if val <= 0 {
			res.Errors = append(res.Errors, fmt.Errorf("param index %s is invalid", p.Position))
			continue
		}
		if val >= len(matches) {
			res.Errors = append(res.Errors, fmt.Errorf("param index %s was not captured (%d elements)", p.Position, len(matches)))
			continue
		}

		res.Values[p.Name] = matches[val]
	}

	// Substitute variable templates in a second pass
	// TODO: Only for param index 0 entries
	for k, v := range res.Values {
		if !varSubPattern.MatchString(v) {
			continue
		}
		nv := varSubPattern.ReplaceAllStringFunc(v, func(s string) string {
			rk := s[1 : len(s)-1]
			r, ok := res.Values[rk]
			if !ok {
				res.Errors = append(res.Errors, fmt.Errorf("param %s could not be substituted", rk))
				return s
			}
			return r
		})
		res.Values[k] = nv
	}

	return res
}

var spacePat = regexp.MustCompile(`\s+`)

// VerifyExamples ensures that the built-in examples match correctly
func (fp *Fingerprint) VerifyExamples() error {

	for _, ex := range fp.Examples {

		exampleData := ex.Text
		encodingType, found := ex.AttributeMap["_encoding"]
		if found {
			switch encodingType {
			case "base64":
				exampleData = spacePat.ReplaceAllString(exampleData, "")
				data, err := base64.StdEncoding.DecodeString(exampleData)
				if err != nil {
					return fmt.Errorf("base64: %s: %s (%s)", fp.PatternCompiled.String(), err, exampleData)
				}
				exampleData = string(data)
			}
		}

		escapedData := strings.Replace(exampleData, "\n", "\\n", -1)
		escapedData = strings.Replace(escapedData, "\r", "\\r", -1)

		m := fp.Match(exampleData)
		if m == nil {
			return fmt.Errorf("failed to match '%s' (%s)", fp.PatternCompiled.String(), string(escapedData))
		}

		if len(m.Errors) > 0 {
			return fmt.Errorf("failed to match '%s' (%s) with errors: %v", fp.PatternCompiled.String(), string(escapedData), m.Errors)
		}

		// Verify that the extracted Values matched
		for k, v := range ex.AttributeMap {
			if k == "_encoding" {
				continue
			}

			verify, ok := m.Values[k]
			if !ok {
				return fmt.Errorf("'%s' %s is missing attribute %s", fp.Pattern, string(escapedData), k)
			}
			if verify != v {
				return fmt.Errorf("'%s' (%s) has mismatched attribute value for %s: %s != %s", fp.Pattern, string(escapedData), k, v, verify)
			}
		}
	}

	return nil
}

// FingerprintMatch represents a match of a fingerprint to some data
type FingerprintMatch struct {
	Matched bool
	Errors  []error
	Values  map[string]string
}

// FingerprintDB represents a fingerprint database
type FingerprintDB struct {
	Matches      string         `xml:"matches,attr" json:"matches,omitempty"`
	Protocol     string         `xml:"protocol,attr" json:"protocol,omitempty"`
	DatabaseType string         `xml:"database_type,attr" json:"database_type,omitempty"`
	Preference   string         `xml:"preference,attr" json:"preference,omitempty"`
	Fingerprints []*Fingerprint `xml:"fingerprint,omitempty" json:"fingerprint,omitempty"`
	Name         string         `json:"name,omitempty"`
	Logger       *log.Logger    `json:"-"`
}

// DebugLog writes an error to the debug log, if enabled
func (fdb *FingerprintDB) DebugLog(format string, args ...interface{}) {
	if fdb.Logger == nil {
		return
	}
	fargs := []interface{}{fdb.Name}
	fargs = append(fargs, args...)
	fdb.Logger.Printf("[recog] %s "+strings.TrimSpace(format), fargs...)
}

// Normalize calls the Normalize function on each loaded Fingerprint
func (fdb *FingerprintDB) Normalize() error {
	for _, fp := range fdb.Fingerprints {
		err := fp.Normalize()
		if err != nil {
			fdb.DebugLog("failed to normalize %s: %s", fdb.Name, err)
			return err
		}

		// Default the fingerprint certainty to the database-level preference
		if fdb.Preference != "" && fp.Certainty == "" {
			fp.Certainty = fdb.Preference
		}
	}
	return nil
}

// VerifyExamples calls the VerifyExamples function on each loaded Fingerprint
func (fdb *FingerprintDB) VerifyExamples() error {
	for _, fp := range fdb.Fingerprints {
		err := fp.VerifyExamples()
		if err != nil {
			fdb.DebugLog("failed to verify examples for %s: %s", fdb.Name, err)
			return err
		}
	}
	return nil
}

// MatchFirst finds the first match for a given string
func (fdb *FingerprintDB) MatchFirst(data string) *FingerprintMatch {
	nomatch := &FingerprintMatch{Matched: false}
	for _, f := range fdb.Fingerprints {
		m := f.Match(data)
		if m.Matched {
			desc := ""
			if f.Description != nil {
				desc = f.Description.Text
			}
			fdb.DebugLog("FP-MATCH %#v to %#v (%s)", data, f.Pattern, desc)
			return m
		}
	}
	fdb.DebugLog("FP-FAIL %#v", data)
	return nomatch
}

// MatchAll finds all matches for a given string
func (fdb *FingerprintDB) MatchAll(data string) []*FingerprintMatch {
	ret := []*FingerprintMatch{}
	for _, f := range fdb.Fingerprints {
		m := f.Match(data)
		if m.Matched {
			desc := ""
			if f.Description != nil {
				desc = f.Description.Text
			}
			fdb.DebugLog("FP-MATCH %#v to %#v (%s)", data, f.Pattern, desc)
			ret = append(ret, m)
		}
	}
	if len(ret) == 0 {
		fdb.DebugLog("FP-FAIL %#v", data)
	}
	return ret
}

// LoadFingerprintDBFromFile parses a Recog XML file from disk and returns a FingerprintDB
func LoadFingerprintDBFromFile(fpath string) (FingerprintDB, error) {
	fdb := FingerprintDB{}

	xmlData, err := ioutil.ReadFile(fpath)
	if err != nil {
		fdb.DebugLog("failed to load fdb from file %s: %s", fpath, err)
		return fdb, err
	}

	fdb.DebugLog("loaded from file %s", fpath)
	return LoadFingerprintDB(filepath.Base(fpath), xmlData)
}

// LoadFingerprintDB parses a Recog XML file from a byte array and returns a FingerprintDB
func LoadFingerprintDB(name string, xmlData []byte) (FingerprintDB, error) {
	fdb := FingerprintDB{}
	err := xml.Unmarshal(xmlData, &fdb)
	if err != nil {
		return fdb, err
	}

	// Store the source name
	fdb.Name = name

	// Normalize the fingerprints
	err = fdb.Normalize()
	if err != nil {
		return fdb, err
	}

	return fdb, nil
}
