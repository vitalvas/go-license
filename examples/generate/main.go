package main

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"log"
	"time"

	"github.com/vitalvas/go-license"
)

func main() {
	privateKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		log.Fatal(err)
	}

	lic := license.NewGenerate()
	lic.LoadPrivateKey(privateKey)

	lic.Set("org.name", "ACME inc")
	lic.Set("org.email", "acme@example.com")

	lic.SetID("e79ac885-de88-4c09-a2bc-7eca47a069bf")

	lic.SetExpired(time.Now().Add(14 * 24 * time.Hour))

	lic.SetFeature("api")
	lic.SetFeature("api.auth.google")
	lic.SetFeature("api.auth.ldap")

	lic.SetRestriction("core.users.max", 123)
	lic.SetRestriction("module.auth.ldap.directory.max", 1)

	key, err := lic.GetLicenseKey()
	if err != nil {
		log.Fatal(err)
	}

	fmt.Println(string(key))
}
