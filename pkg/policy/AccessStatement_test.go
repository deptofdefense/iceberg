// =================================================================
//
// Work of the U.S. Department of Defense, Defense Digital Service.
// Released as open source under the MIT License.  See LICENSE file.
//
// =================================================================

package policy

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestStatement(t *testing.T) {
	u := loadTestUser()
	t.Run("AllowAll", func(t *testing.T) {
		s := AccessStatementDefaultAllow
		//
		assert.NoError(t, s.Validate())
		//
		assert.True(t, s.MatchUser(u))
		assert.True(t, s.MatchUser(&User{}))
		//
		assert.True(t, s.MatchPath("/hello/world"))
		assert.True(t, s.MatchPath("/"))
		assert.True(t, s.MatchPath(""))
	})
	//
	t.Run("AllowWildcardPath", func(t *testing.T) {
		s := AccessStatement{
			Effect:   Allow,
			Paths:    []string{Wildcard},
			Users:    []string{u.DistinguishedName()},
			NotUsers: []string{},
		}
		//
		assert.NoError(t, s.Validate())
		//
		assert.True(t, s.MatchUser(u))
		assert.False(t, s.MatchUser(&User{}))
		//
		assert.True(t, s.MatchPath("/hello/world"))
		assert.True(t, s.MatchPath("/"))
		assert.True(t, s.MatchPath(""))
	})
	//
	t.Run("AllowPathAndUser", func(t *testing.T) {
		s := AccessStatement{
			Effect:   Allow,
			Paths:    []string{filepath.Join("/", "hello", Wildcard)},
			Users:    []string{u.DistinguishedName()},
			NotUsers: []string{},
		}
		//
		assert.NoError(t, s.Validate())
		//
		assert.True(t, s.MatchUser(u))
		assert.False(t, s.MatchUser(&User{}))
		//
		assert.True(t, s.MatchPath("/hello/world"))
		assert.False(t, s.MatchPath("/"))
		assert.False(t, s.MatchPath(""))
	})
	//
	t.Run("DenyPathAndNotUser", func(t *testing.T) {
		s := AccessStatement{
			Effect:   Deny,
			Paths:    []string{filepath.Join("/", "denied")},
			Users:    []string{},
			NotUsers: []string{"abc"},
		}
		//
		assert.NoError(t, s.Validate())
		//
		assert.True(t, s.MatchNotUser(u))
		assert.True(t, s.MatchNotUser(&User{}))
		//
		assert.True(t, s.MatchPath("/denied"))
	})
	//
	t.Run("MissingPaths", func(t *testing.T) {
		s := AccessStatement{
			Effect:   Allow,
			Paths:    []string{},
			Users:    []string{u.DistinguishedName()},
			NotUsers: []string{},
		}
		//
		assert.Error(t, s.Validate())
	})
	//
	t.Run("MissingUsers", func(t *testing.T) {
		s := AccessStatement{
			Effect:   Allow,
			Paths:    []string{Wildcard},
			Users:    []string{},
			NotUsers: []string{},
		}
		//
		assert.Error(t, s.Validate())
	})
	//
	t.Run("UsersAndNotUsers", func(t *testing.T) {
		s := AccessStatement{
			Effect:   Allow,
			Paths:    []string{Wildcard},
			Users:    []string{Wildcard},
			NotUsers: []string{Wildcard},
		}
		//
		assert.Error(t, s.Validate())
	})
}
