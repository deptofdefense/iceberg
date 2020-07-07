// =================================================================
//
// Work of the U.S. Department of Defense, Defense Digital Service.
// Released as open source under the MIT License.  See LICENSE file.
//
// =================================================================

package policy

import (
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io/ioutil"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/assert"
)

func loadTestKeyPair() *x509.Certificate {
	b, err := ioutil.ReadFile("testdata/test.cert")
	if err != nil {
		panic(err)
	}
	block, _ := pem.Decode(b)
	if block == nil {
		panic("failed to parse certificate PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		panic(fmt.Errorf("failed to parse certificate: %w", err))
	}
	return cert
}

func loadTestUser() *User {
	keyPair := loadTestKeyPair()
	return &User{
		Subject: keyPair.Subject,
	}
}

func TestPolicy(t *testing.T) {
	u := loadTestUser()
	//
	t.Run("DefaultAllow", func(t *testing.T) {
		p := AccessPolicyDefaultAllow
		//
		assert.True(t, p.Evaluate("/hello/world", u))
		assert.True(t, p.Evaluate("/", u))
		assert.True(t, p.Evaluate("", u))
		//
		assert.True(t, p.Evaluate("/hello/world", u))
		assert.True(t, p.Evaluate("/", u))
		assert.True(t, p.Evaluate("", u))
	})
	//
	t.Run("DefaultDeny", func(t *testing.T) {
		p := AccessPolicyDefaultDeny
		//
		assert.False(t, p.Evaluate("/hello/world", u))
		assert.False(t, p.Evaluate("/", u))
		assert.False(t, p.Evaluate("", u))
		//
		assert.False(t, p.Evaluate("/hello/world", u))
		assert.False(t, p.Evaluate("/", u))
		assert.False(t, p.Evaluate("", u))
	})
	//
	t.Run("DenyPath", func(t *testing.T) {
		p := AccessPolicyDefaultAllow
		p.Statements = append(p.Statements, AccessStatement{
			Effect: Deny,
			Paths:  []string{filepath.Join("/", "hello", "world")},
			Users:  []string{"*"},
		})
		//
		assert.False(t, p.Evaluate("/hello/world", u))
		assert.True(t, p.Evaluate("/", u))
		assert.True(t, p.Evaluate("", u))
		//
	})
	t.Run("DenyPathNotUser", func(t *testing.T) {
		p := AccessPolicyDefaultAllow
		p.Statements = append(p.Statements, AccessStatement{
			Effect:   Deny,
			Paths:    []string{filepath.Join("/", "hello", "world")},
			NotUsers: []string{"abc"},
		})
		//
		assert.False(t, p.Evaluate("/hello/world", u))
		//
	})

}
