package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"time"

	"github.com/vitalvas/go-license/license"
)

func main() {
	filePath := flag.String("file", "", "Path to the file to analyze")
	flag.Parse()

	if *filePath == "" {
		flag.PrintDefaults()
		return
	}

	lic, err := license.DecodeFile(*filePath)
	if err != nil {
		log.Fatal(err)
	}

	if lic.ID != "" {
		fmt.Println("License ID:", lic.ID)
	}

	if lic.Customer != "" {
		fmt.Println("License Customer:", lic.Customer)
	}

	if lic.Subscription != "" {
		fmt.Println("License Subscription:", lic.Subscription)
	}

	if lic.Type != "" {
		fmt.Println("License Type:", lic.Type)
	}

	if lic.IssuedAt > 0 {
		unixTimeUTC := time.Unix(lic.IssuedAt, 0)
		fmt.Printf("License Issued At: %d (%s) \n", lic.IssuedAt, unixTimeUTC.Format("2006-01-02 15:04:05 Z07:00"))
	}

	if lic.ExpiredAt > 0 {
		unixTimeUTC := time.Unix(lic.ExpiredAt, 0)
		fmt.Printf("License Expires At: %d (%s) \n", lic.ExpiredAt, unixTimeUTC.Format("2006-01-02 15:04:05 Z07:00"))
	}

	if lic.Data != nil {
		var data map[string]interface{}

		if err := json.Unmarshal(lic.Data, &data); err != nil {
			log.Fatal(err)
		}

		payload, err := json.MarshalIndent(data, "", "  ")
		if err != nil {
			log.Fatal(err)
		}

		fmt.Println("License Data:")
		fmt.Println(string(payload))
	}
}
