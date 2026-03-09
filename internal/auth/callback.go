package auth

import (
	"context"
	"fmt"
	"net"
	"net/http"
	"sync"
)

// CallbackResult holds the result of an OAuth authorization callback.
type CallbackResult struct {
	Code  string
	State string
	Error string
}

// StartCallbackServer starts a localhost HTTP server that handles the OAuth
// callback. If preferredPort > 0, it tries that port first (to reuse a port
// from a previous dynamic client registration). If the preferred port is
// unavailable it falls back to an ephemeral port. It returns the port, a
// channel that receives the callback result, and a shutdown function.
func StartCallbackServer(ctx context.Context, host, expectedState string, preferredPort int) (port int, result <-chan CallbackResult, shutdown func(), err error) {
	var ln net.Listener

	if preferredPort > 0 {
		ln, err = net.Listen("tcp", fmt.Sprintf("%s:%d", host, preferredPort))
		if err != nil {
			// Preferred port unavailable — fall back to ephemeral.
			ln = nil
		}
	}

	if ln == nil {
		ln, err = net.Listen("tcp", host+":0")
		if err != nil {
			return 0, nil, nil, fmt.Errorf("auth: listen on %s: %w", host, err)
		}
	}

	port = ln.Addr().(*net.TCPAddr).Port
	ch := make(chan CallbackResult, 1)
	var once sync.Once

	send := func(r CallbackResult) {
		once.Do(func() { ch <- r })
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/callback", func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()

		if oauthErr := q.Get("error"); oauthErr != "" {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusOK)
			fmt.Fprint(w, "<html><body><h1>Authorization failed.</h1><p>You may close this window.</p></body></html>")
			send(CallbackResult{Error: oauthErr})
			return
		}

		state := q.Get("state")
		if state != expectedState {
			w.Header().Set("Content-Type", "text/html")
			w.WriteHeader(http.StatusBadRequest)
			fmt.Fprint(w, "<html><body><h1>State mismatch.</h1><p>You may close this window.</p></body></html>")
			send(CallbackResult{Error: "state mismatch"})
			return
		}

		code := q.Get("code")
		w.Header().Set("Content-Type", "text/html")
		w.WriteHeader(http.StatusOK)
		fmt.Fprint(w, "<html><body><h1>Authorization complete.</h1><p>You may close this window.</p></body></html>")
		send(CallbackResult{Code: code, State: state})
	})

	server := &http.Server{Handler: mux}

	shutdownFn := func() {
		server.Shutdown(context.Background())
	}

	go func() {
		<-ctx.Done()
		shutdownFn()
	}()

	go server.Serve(ln)

	return port, ch, shutdownFn, nil
}
