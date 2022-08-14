# Recog-Go: Pattern Recognition using Rapid7 Recog

This is a Go implementation of the [Recog](https://github.com/rapid7/recog/) library and fingerprint database from Rapid7.

This package requires a checkout of the recog repository in order to build.

Recog-Go is open source, please see the [LICENSE](https://raw.githubusercontent.com/runZeroInc/recog-go/master/LICENSE) file for more information.

To build and install:
```
$ git clone https://github.com/rapid7/recog.git /path/to/recog
$ RECOG_XML=/path/to/recog/xml go generate
$ go install . ./cmd/...
```
