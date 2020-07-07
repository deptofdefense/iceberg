// =================================================================
//
// Work of the U.S. Department of Defense, Defense Digital Service.
// Released as open source under the MIT License.  See LICENSE file.
//
// =================================================================

package server

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestCheckPath(t *testing.T) {
	// valid paths
	assert.True(t, CheckPath("abc"))
	assert.True(t, CheckPath("hello/world"))
	assert.True(t, CheckPath("hello/world.txt"))
	assert.True(t, CheckPath("hello/world.txt"))
	// invalid paths
	assert.False(t, CheckPath("../"))
	assert.False(t, CheckPath("../hello/world"))
	assert.False(t, CheckPath("hello/world/.."))
	assert.False(t, CheckPath("hello/../../world"))
}
