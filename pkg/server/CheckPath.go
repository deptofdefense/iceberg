// =================================================================
//
// Work of the U.S. Department of Defense, Defense Digital Service.
// Released as open source under the MIT License.  See LICENSE file.
//
// =================================================================

package server

import (
	"path/filepath"
	"strings"
)

// CheckPath returns true if the given path is ok, which means the path contains no "." or ".." path elements.
func CheckPath(path string) bool {
	// If the path includes a ".." element, filePath.Clean will return a different string.
	// If the path starts with "../", then it points to a parent directory.
	return path == filepath.Clean(path) && !strings.HasPrefix(path, "../")
}
