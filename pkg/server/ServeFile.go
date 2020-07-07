// =================================================================
//
// Work of the U.S. Department of Defense, Defense Digital Service.
// Released as open source under the MIT License.  See LICENSE file.
//
// =================================================================

package server

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/spf13/afero"
)

func ServeFile(w http.ResponseWriter, r *http.Request, fs afero.Fs, p string, modtime time.Time, download bool, errorHandler func(w http.ResponseWriter, r *http.Request, err error) error) {
	f, err := fs.Open(p)
	if err != nil {
		if errorHandler != nil {
			err = errorHandler(w, r, err)
			if err == nil {
				return
			}
		}
		_, _ = fmt.Fprintln(os.Stderr, fmt.Errorf("error opening file from path %q: %w", p, err).Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Cache-Control", "no-cache")
	if download {
		w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filepath.Base(p)))
	}
	http.ServeContent(w, r, filepath.Base(p), modtime, f)
}
