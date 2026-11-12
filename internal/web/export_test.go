package web

import "time"

// SetReadyTimeout lets external tests shorten the /readyz deadline.
func (w *Web) SetReadyTimeout(d time.Duration) { w.readyTimeout = d }
