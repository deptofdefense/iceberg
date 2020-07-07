// =================================================================
//
// Work of the U.S. Department of Defense, Defense Digital Service.
// Released as open source under the MIT License.  See LICENSE file.
//
// =================================================================

package certs

import (
	"crypto/x509"
	"fmt"
	"io/ioutil"
)

func LoadCertPool(path string, format string) (*x509.CertPool, error) {
	b, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("error reading cert pool from path %q: %w", path, err)
	}
	if format == "pkcs7" {
		pool, err := LoadCertPoolFromPkcs7Package(b)
		if err != nil {
			return nil, fmt.Errorf("error parsing cert pool from path %q: %w", path, err)
		}
		return pool, nil
	}
	if format == "pem" {
		return LoadCertPoolFromPEM(b), nil
	}
	return nil, fmt.Errorf("unknown cert pool format %q", format)
}
