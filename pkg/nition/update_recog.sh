#!/bin/bash

git add recog && git commit -a -m "recog updates" && go generate ./... && git commit -a -m "regenerate resources"
