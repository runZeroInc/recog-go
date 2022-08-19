package recog

import (
	"regexp"
	"strconv"
	"strings"
	"testing"
)

func TestFingerprints(t *testing.T) {
	reParamName := regexp.MustCompile("^(?:cookie|[^\\.]+\\..*)$")
	reGroupedMultiline := regexp.MustCompile(".+\\(\\?[gixsu]*m[gixsu]*:[^)]*\\)")
	reGroupedCaseSensitivity := regexp.MustCompile(".+\\(\\?[gmxsu]*i[gmxsu]*:[^)]*\\)")
	reInterpolation := regexp.MustCompile("\\{(?P<interpolated>[^\\s{}]+)\\}")

	fset, err := LoadFingerprints()
	if err != nil {
		t.Fatalf("LoadFingerprints() failed:: %s", err)
	}

	for name, fdb := range fset.Databases {
		name := name
		fdb := fdb
		if !strings.HasSuffix(name, ".xml") {
			continue
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			if preference, err := strconv.ParseFloat(fdb.Preference, 32); err == nil && (preference <= .1 || preference > .9) {
				t.Error("fingerprint db preference should be between 0.1 - 0.9")
			}

			descriptions := make(set)
			for i, fp := range fdb.Fingerprints {
				i := i
				fp := fp
				if fp.Description == nil {
					t.Errorf("has nil description: %v", fp)
					continue
				}
				if descriptions.contains(fp.Description.Text) {
					t.Errorf("has a duplicate fingerprint description: %q", fp.Description.Text)
				} else {
					descriptions.add(fp.Description.Text)
				}

				if len(fp.Params) == 0 {
					t.Errorf("should assert facts about data or set certainty params to 0.0: %v", fp.Description.Text)
				}

				t.Run(fp.Description.Text, func(t *testing.T) {
					if reGroupedCaseSensitivity.MatchString(fp.Pattern) {
						t.Errorf("regex case-sensitivity flag should be at the start of the regex: %s", fp.Pattern)
					}

					if reGroupedMultiline.MatchString(fp.Pattern) {
						t.Errorf("regex multiline flag should be at the start of the regex: %s", fp.Pattern)
					}

					params := make(set)
					captures := make(set)
					var hwDevice, osDevice string
					for _, param := range fp.Params {
						param := param
						pos, _ := strconv.Atoi(param.Position)
						val := strings.TrimSpace(param.Value)
						if !reParamName.MatchString(param.Name) {
							t.Errorf("fingerprint parameter name is invalid: %q", param.Name)
						} else if params.contains(param.Name) {
							t.Errorf("has a duplicate fingerprint parameter: %q", param.Name)
						} else {
							params.add(param.Name)
						}

						if param.Name == "os.device" {
							osDevice = val
						} else if param.Name == "hw.device" {
							hwDevice = val
						}

						if pos > 0 {
							captures.add(pos)
						}

						if pos > 0 && val != "" {
							t.Errorf("parameter %q is set from a capture group(%d), but a value was provided", param.Name, pos)
						}

						if pos == 0 && val == "" {
							t.Errorf("%s is not a capture (pos=0) but no value was provided", param.Name)
						}

						if pos == 0 && reInterpolation.MatchString(val) {
							found := false
							match := reInterpolation.FindStringSubmatch(val)
							interpolated := match[reInterpolation.SubexpIndex("interpolated")]
							for _, p := range fp.Params {
								if p.Name == interpolated {
									found = true
								}
							}
							if !found {
								t.Errorf("%q uses interpolated value %q that does not exist in list of fingerprint parameters", param.Name, interpolated)
							}
						}
					}

					if (hwDevice != "" && osDevice != "") && osDevice != hwDevice {
						t.Errorf("has both hw.device and os.device but with differing values")
					}

					captureGroups := captures.len()
					if fp.PatternCompiled.NumSubexp() != captureGroups {
						t.Errorf("regex has %d capture groups, but the fingerprint expected %d extraction(s)", fp.PatternCompiled.NumSubexp(), captureGroups)
					}

					if i == 0 {
						return
					}

					for j := 0; j < i; j++ {
						previousFp := fdb.Fingerprints[j]
						for _, example := range fp.Examples {
							if match := previousFp.Match(example.Text); match.Matched {
								t.Errorf("regex matched previous fingerprint: %s; consider reordering the fingerprints", previousFp.Description.Text)
							}
						}
					}
				})
			}
		})
	}
}

type set map[interface{}]struct{}

func (s *set) add(v interface{}) {
	if _, ok := (*s)[v]; !ok {
		(*s)[v] = struct{}{}
	}
}

func (s *set) contains(v interface{}) bool {
	if _, ok := (*s)[v]; ok {
		return true
	}
	return false
}

func (s *set) len() int {
	return len(*s)
}
