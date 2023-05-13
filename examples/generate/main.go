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
	"github.com/vitalvas/go-license/license/licenseutil"
)

var privateKey ed25519.PrivateKey
var publicKey ed25519.PublicKey
var err error

func init() {
	publicKey, privateKey, err = ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
}

func main() {
	verify(generate())
}

type licenseContent struct {
	Org struct {
		Name  string `json:"name"`
		Email string `json:"email"`
	} `json:"org"`
	Features []string       `json:"features"`
	Limits   map[string]int `json:"limits"`
}

func generate() []byte {
	lic := licenseutil.NewGenerate()
	lic.LoadPrivateKey(privateKey)

	licData := licenseContent{}

	licData.Org.Name = "ACME inc"
	licData.Org.Email = "acme@example.com"

	licData.Features = []string{
		"api",
		"api.auth.google",
		"api.auth.ldap",
	}

	licData.Limits = map[string]int{
		"core.users.max":                 123,
		"module.auth.ldap.directory.max": 1,
	}

	lic.SetID("e79ac885-de88-4c09-a2bc-7eca47a069bf")

	lic.SetExpired(time.Now().Add(14 * 24 * time.Hour))

	if err := lic.SetData(licData); err != nil {
		log.Fatal(err)
	}

	key, err := lic.GetLicenseKey()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(strings.TrimSpace(string(key)))

	return key
}

func verify(key []byte) {
	load := licenseutil.Load(key)
	load.LoadPublicKey(publicKey)

	lic, err := load.GetLicense()
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
