package license

import "errors"

var (
	ErrMalformedLicense    = errors.New("malformed license")
	ErrWrongVerifyChecksum = errors.New("wrong verify checksum")
	ErrVerifySignature     = errors.New("error verify signature")
	ErrWrongVerifyID       = errors.New("wrong verify id")

	ErrLicenseIDNotDefined  = errors.New("license id not defined")
	ErrTime                 = errors.New("the expire time must be greater than the issue time")
	ErrPrivateKeyNotDefined = errors.New("private key not defined")
)
