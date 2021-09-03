package main

import (
	"log"
	"net/http"
	"os"

	"github.com/shurcooL/vfsgen"
)

func main() {
	xmlPath := "./recog/xml"
	if v := os.Getenv("RECOG_XML"); v != "" {
		xmlPath = v
	}
	err := vfsgen.Generate(http.Dir(xmlPath), vfsgen.Options{
		PackageName:  "recog",
		VariableName: "RecogXML",
	})
	if err != nil {
		log.Fatalln(err)
	}
}
