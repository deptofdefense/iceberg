package certs

import (
	"crypto/x509"
	"encoding/pem"
	"io/ioutil"
)

// ParseCert returns an x509.Certificate from a file
func ParseCert(filename string) (*x509.Certificate, error) {
	r, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(r)
	cert, err := x509.ParseCertificate(block.Bytes)
	return cert, err
}
