// =================================================================
//
// Work of the U.S. Department of Defense, Defense Digital Service.
// Released as open source under the MIT License.  See LICENSE file.
//
// =================================================================

package certs

import (
	"fmt"
	"strings"

	"crypto/x509/pkix"
)

func DistinguishedName(name pkix.Name) string {
	terms := make([]string, 0)
	for _, n := range name.Names {
		if n.Type.Equal([]int{2, 5, 4, 6}) {
			terms = append(terms, fmt.Sprintf("/C=%s", n.Value))
		} else if n.Type.Equal([]int{2, 5, 4, 10}) {
			terms = append(terms, fmt.Sprintf("/O=%s", n.Value))
		} else if n.Type.Equal([]int{2, 5, 4, 11}) {
			terms = append(terms, fmt.Sprintf("/OU=%s", n.Value))
		} else if n.Type.Equal([]int{2, 5, 4, 3}) {
			terms = append(terms, fmt.Sprintf("/CN=%s", n.Value))
		} else if n.Type.Equal([]int{2, 5, 4, 7}) {
			terms = append(terms, fmt.Sprintf("/L=%s", n.Value))
		} else if n.Type.Equal([]int{2, 5, 4, 8}) {
			terms = append(terms, fmt.Sprintf("/ST=%s", n.Value))
		} else if n.Type.Equal([]int{1, 2, 840, 113549, 1, 9, 1}) {
			terms = append(terms, fmt.Sprintf("/E=%s", n.Value))
		} else {
			terms = append(terms, fmt.Sprintf("/%s=%s", n.Type, n.Value))
		}
	}
	return strings.Join(terms, "")
}
