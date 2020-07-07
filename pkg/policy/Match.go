// =================================================================
//
// Work of the U.S. Department of Defense, Defense Digital Service.
// Released as open source under the MIT License.  See LICENSE file.
//
// =================================================================

package policy

import (
	"strings"
)

// Match checks that the value matches the given pattern with support for wildcard expressions.
// The wildcard character is "*".
// The wildcard character can only be used once in a pattern.
// If the pattern equals the wildcard chracter, then the function always returns true.
// If the pattern ends with the wild card character, e.g., a/b/*, then it matches the prefix of the value.
// If the pattern starts with the wild card character, e.g., *.ext, then it matches the suffix of the value.
// If no wildcard is present, then it checks if the pattern equals the value.
func Match(pattern string, value string) bool {
	// If pattern equals wildcard.
	if pattern == Wildcard {
		return true
	}
	// If pattern starts with wildcard
	if strings.HasSuffix(pattern, Wildcard) {
		return strings.HasPrefix(value, pattern[0:len(pattern)-1])
	}
	// If pattern ends with wildcard
	if strings.HasPrefix(pattern, Wildcard) {
		return strings.HasSuffix(value, pattern[1:])
	}
	// Return true if pattern equals value
	return pattern == value
}
