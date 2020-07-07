// =================================================================
//
// Work of the U.S. Department of Defense, Defense Digital Service.
// Released as open source under the MIT License.  See LICENSE file.
//
// =================================================================

package server

import (
	"fmt"
	"html/template"
	"net/http"
	"os"
)

func ServeTemplate(w http.ResponseWriter, r *http.Request, tmpl *template.Template, ctx interface{}) {
	w.Header().Set("Cache-Control", "no-cache")
	err := tmpl.Execute(w, ctx)
	if err != nil {
		_, _ = fmt.Fprintln(os.Stderr, fmt.Errorf("error executing directory listing template for path %q: %w", r.URL.Path, err).Error())
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
}
