// =================================================================
//
// Work of the U.S. Department of Defense, Defense Digital Service.
// Released as open source under the MIT License.  See LICENSE file.
//
// =================================================================

package certs

import (
	"bytes"
	"crypto/x509"
)

func LoadCertPoolFromPEM(b []byte) *x509.CertPool {
	clientCAs := x509.NewCertPool()
	clientCAs.AppendCertsFromPEM(bytes.TrimSpace(b))
	return clientCAs
}
