// =================================================================
//
// Work of the U.S. Department of Defense, Defense Digital Service.
// Released as open source under the MIT License.  See LICENSE file.
//
// =================================================================

package server

import (
	"strings"
	"unicode"
)

func CleanPath(str string) string {
	out := make([]rune, 0)
	for _, x := range strings.TrimSpace(str) {
		if unicode.IsSpace(x) {
			out = append(out, ' ')
			continue
		}
		if unicode.IsPrint(x) {
			out = append(out, x)
			continue
		}
	}
	return string(out)
}
