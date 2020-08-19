// =================================================================
//
// Work of the U.S. Department of Defense, Defense Digital Service.
// Released as open source under the MIT License.  See LICENSE file.
//
// =================================================================

package policy

import (
	"fmt"
	"strings"

	"crypto/x509/pkix"
)

var (
	TypeCountry            = []int{2, 5, 4, 6}
	TypeOrganization       = []int{2, 5, 4, 10}
	TypeOrganizationalUnit = []int{2, 5, 4, 11}
	TypeCommonName         = []int{2, 5, 4, 3}
	TypeLocality           = []int{2, 5, 4, 7}
	TypeState              = []int{2, 5, 4, 8}
	TypeEmail              = []int{1, 2, 840, 113549, 1, 9, 1}
)

type User struct {
	Subject pkix.Name
}

// DistinguishedName returns the user subject as a DistinguishedName.
// See https://docs.microsoft.com/en-us/windows/win32/seccrypto/name-properties
func (u *User) DistinguishedName() string {
	terms := make([]string, 0)
	for _, n := range u.Subject.Names {
		if n.Type.Equal(TypeCountry) {
			terms = append(terms, fmt.Sprintf("/C=%s", n.Value))
		} else if n.Type.Equal(TypeOrganization) {
			terms = append(terms, fmt.Sprintf("/O=%s", n.Value))
		} else if n.Type.Equal(TypeOrganizationalUnit) {
			terms = append(terms, fmt.Sprintf("/OU=%s", n.Value))
		} else if n.Type.Equal(TypeCommonName) {
			terms = append(terms, fmt.Sprintf("/CN=%s", n.Value))
		} else if n.Type.Equal(TypeLocality) {
			terms = append(terms, fmt.Sprintf("/L=%s", n.Value))
		} else if n.Type.Equal(TypeState) {
			terms = append(terms, fmt.Sprintf("/ST=%s", n.Value))
		} else if n.Type.Equal(TypeEmail) {
			terms = append(terms, fmt.Sprintf("/E=%s", n.Value))
		} else {
			terms = append(terms, fmt.Sprintf("/%s=%s", n.Type, n.Value))
		}
	}
	return strings.Join(terms, "")
}

// ParseUser parses the the user subject as a DistinguishedName.
// See https://docs.microsoft.com/en-us/windows/win32/seccrypto/name-properties
// Todo: (1) fill in the other fields for the user, and (2) parse unknown names.
func ParseUser(str string) *User {
	terms := strings.Split(str, "/")
	u := &User{
		Subject: pkix.Name{
			Names:      []pkix.AttributeTypeAndValue{},
			ExtraNames: []pkix.AttributeTypeAndValue{},
		},
	}
	for _, t := range terms {
		if len(t) > 0 {
			parts := strings.SplitN(t, "=", 2)
			switch strings.ToUpper(parts[0]) {
			case "C":
				u.Subject.Names = append(u.Subject.Names, pkix.AttributeTypeAndValue{
					Type:  TypeCountry,
					Value: parts[1],
				})
			case "O":
				u.Subject.Names = append(u.Subject.Names, pkix.AttributeTypeAndValue{
					Type:  TypeOrganization,
					Value: parts[1],
				})
			case "OU":
				u.Subject.Names = append(u.Subject.Names, pkix.AttributeTypeAndValue{
					Type:  TypeOrganizationalUnit,
					Value: parts[1],
				})
			case "CN":
				u.Subject.Names = append(u.Subject.Names, pkix.AttributeTypeAndValue{
					Type:  TypeCommonName,
					Value: parts[1],
				})
			case "L":
				u.Subject.Names = append(u.Subject.Names, pkix.AttributeTypeAndValue{
					Type:  TypeLocality,
					Value: parts[1],
				})
			case "ST":
				u.Subject.Names = append(u.Subject.Names, pkix.AttributeTypeAndValue{
					Type:  TypeState,
					Value: parts[1],
				})
			case "E":
				u.Subject.Names = append(u.Subject.Names, pkix.AttributeTypeAndValue{
					Type:  TypeEmail,
					Value: parts[1],
				})
			default:
			}
		}
	}
	return u
}
