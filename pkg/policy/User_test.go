// =================================================================
//
// Work of the U.S. Department of Defense, Defense Digital Service.
// Released as open source under the MIT License.  See LICENSE file.
//
// =================================================================

package policy

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestUser(t *testing.T) {
	u := loadTestUser()
	assert.Equal(t, "/C=US/ST=Pacific Shelf/L=Atlantis/O=City of Atlantis/OU=Atlantis Digital Service/CN=atlantis.example.com/E=hello@atlantis.example.com", u.DistinguishedName())
}
