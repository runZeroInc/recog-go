#!/bin/bash

(cd recog && git commit -a -m "fingerprint updates") && \
git add recog && git commit -a -m "recog updates" && go generate ./... && git commit -a -m "regenerate resources"
