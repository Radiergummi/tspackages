// Package ecosystem defines what every package ecosystem plugs into the server.
package ecosystem

import "net/http"

// Ecosystem is one package format served by tspackages.
type Ecosystem interface {
	Name() string
	Mount(mux *http.ServeMux)
}
