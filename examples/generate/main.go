package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"log"
	"strings"
	"time"

	"github.com/davecgh/go-spew/spew"
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
	Features []string          `json:"features"`
	Limits   map[string]int    `json:"limits"`
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

	fmt.Printf("\n---\n\n")

	spew.Dump(lic)

	var licData licenseContent
	if err := json.Unmarshal(lic.Data, &licData); err != nil {
		log.Fatal(err)
	}

	fmt.Printf("\n---\n\n")

	spew.Dump(licData)
}
