package githttp

import (
	"encoding/json"
	"net/http"
)

// AdminMux builds the operational endpoint set.
//
// These are served on their own listener, away from the address
// developers push to: /metrics describes the organisation's security
// posture -- block rates, which scanners fire -- and is not something to
// hand to everyone who holds a push token.
func AdminMux(metricsHandler http.Handler, ready func() error, version string) *http.ServeMux {
	mux := http.NewServeMux()

	if metricsHandler != nil {
		mux.Handle("/metrics", metricsHandler)
	}

	// Liveness: the process is up. It must not depend on anything
	// external, or a database blip would have an orchestrator restart a
	// gateway that is working fine.
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{
			"status":  "ok",
			"version": version,
		})
	})

	// Readiness: the gateway can actually serve a push. This one does
	// check its dependencies, so a failing instance is taken out of
	// rotation rather than rejecting pushes.
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, _ *http.Request) {
		if ready != nil {
			if err := ready(); err != nil {
				writeJSON(w, http.StatusServiceUnavailable, map[string]string{
					"status": "not ready",
					"error":  err.Error(),
				})
				return
			}
		}
		writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
	})

	return mux
}

func writeJSON(w http.ResponseWriter, code int, body any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(body)
}
