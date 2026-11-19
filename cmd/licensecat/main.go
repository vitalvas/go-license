package main

import (
	"flag"
	"log"
	"os"

	"go.vitalvas.com/go-license/internal/printer"
)

func main() {
	filePath := flag.String("file", "", "Path to the file to analyze")
	flag.Parse()

	if *filePath == "" {
		flag.PrintDefaults()
		return
	}

	if err := printer.Run(os.Stdout, *filePath); err != nil {
		log.Fatal(err)
	}
}
