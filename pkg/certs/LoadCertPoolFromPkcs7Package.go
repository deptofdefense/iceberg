// =================================================================
//
// Work of the U.S. Department of Defense, Defense Digital Service.
// Released as open source under the MIT License.  See LICENSE file.
//
// =================================================================

package certs

import (
	"crypto/x509"

	"go.mozilla.org/pkcs7"
)

func LoadCertPoolFromPkcs7Package(pkcs7Package []byte) (*x509.CertPool, error) {
	p7, err := pkcs7.Parse(pkcs7Package)
	if err != nil {
		return nil, err
	}
	certPool := x509.NewCertPool()
	for _, cert := range p7.Certificates {
		certPool.AddCert(cert)
	}
	return certPool, nil
}
