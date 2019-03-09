package main

import (
	"log"
	"net/http"

	"github.com/shurcooL/vfsgen"
)

func main() {

	err := vfsgen.Generate(http.Dir("./recog/xml"), vfsgen.Options{
		PackageName:  "nition",
		VariableName: "Assets",
	})
	if err != nil {
		log.Fatalln(err)
	}
}
