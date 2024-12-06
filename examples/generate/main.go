package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/vitalvas/go-license/license"
)

func main() {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}

	generateKey := generate(privateKey)

	fmt.Println(strings.TrimSpace(string(generateKey)))

	verify(generateKey, publicKey)
}

type licenseContent struct {
	Org      licenseContentOrg `json:"org"`
	Features []string          `json:"features,omitempty"`
	Limits   map[string]int    `json:"limits,omitempty"`
}

type licenseContentOrg struct {
	Name  string `json:"name"`
	Email string `json:"email"`
}

func generate(privateKey ed25519.PrivateKey) []byte {
	now := time.Now()

	lic := license.License{
		ID:        "e79ac885-de88-4c09-a2bc-7eca47a069bf",
		IssuedAt:  now.Truncate(time.Hour * 24).UTC().Unix(),
		ExpiredAt: now.Add(365 * 24 * time.Hour).Truncate(time.Hour * 24).UTC().Unix(),
	}

	licData := licenseContent{
		Org: licenseContentOrg{
			Name:  "ACME inc",
			Email: "acme@example.com",
		},
		Features: []string{
			"api",
			"api.auth.google",
			"api.auth.ldap",
		},
		Limits: map[string]int{
			"core.users.max":                 123,
			"module.auth.ldap.directory.max": 1,
		},
	}

	payload, err := json.Marshal(licData)
	if err != nil {
		log.Fatal(err)
	}

	lic.Data = payload

	key, err := lic.Encode(privateKey)
	if err != nil {
		log.Fatal(err)
	}

	return key
}

func verify(licenseKey []byte, publicKey ed25519.PublicKey) {
	lic, err := license.Decode(licenseKey, publicKey)
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(strings.Repeat("-", 32))

	licData := lic.Data
	lic.Data = nil

	encoder := json.NewEncoder(os.Stdout)
	encoder.SetIndent("", "  ")

	encoder.Encode(lic)

	fmt.Println(strings.Repeat("-", 32))

	var data licenseContent
	if err := json.Unmarshal(licData, &data); err != nil {
		log.Fatal(err)
	}

	encoder.Encode(data)
}
