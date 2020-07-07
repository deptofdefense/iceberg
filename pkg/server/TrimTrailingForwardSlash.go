// =================================================================
//
// Work of the U.S. Department of Defense, Defense Digital Service.
// Released as open source under the MIT License.  See LICENSE file.
//
// =================================================================

package server

func TrimTrailingForwardSlash(str string) string {
	if len(str) > 1 && str != "//" && str[len(str)-1] == '/' {
		return str[0 : len(str)-1]
	}
	return str
}
