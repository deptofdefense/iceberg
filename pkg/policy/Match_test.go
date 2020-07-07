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

func TestMatch(t *testing.T) {
	assert.True(t, Match("*", "helloworld"))
	assert.True(t, Match("helloworld", "helloworld"))
	assert.False(t, Match("hello", "world"))
	assert.False(t, Match("hello/*", "hello"))
	assert.True(t, Match("hello/*", "hello/"))
	assert.True(t, Match("hello/*", "hello/world"))
	assert.True(t, Match("*hello", "hello"))
	assert.False(t, Match("*.hello", "hello"))
	assert.True(t, Match("*.world", "hello.world"))
	assert.True(t, Match("*.world", "path/to/hello.world"))
}
