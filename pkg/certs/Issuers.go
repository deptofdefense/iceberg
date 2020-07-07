// =================================================================
//
// Work of the U.S. Department of Defense, Defense Digital Service.
// Released as open source under the MIT License.  See LICENSE file.
//
// =================================================================

package certs

import (
	"crypto/x509"
)

func Issuers(certificates []*x509.Certificate) []string {
	subjects := make([]string, 0, len(certificates))
	for _, c := range certificates {
		subjects = append(subjects, DistinguishedName(c.Issuer))
	}
	return subjects
}
