package web

import (
	"bufio"
	"fmt"
	"net/http"
	"strings"
)

func ServerSentEventHandler(hub *Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming Not Supported", http.StatusInternalServerError)
			return
		}

		// Mandatory SSE http response headers
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no")

		clientchan := make(chan Message, 16)
		hub.register <- clientchan

		defer func() {
			hub.unregister <- clientchan
		}()

		ctx := r.Context()
		for {
			select {
			case <-ctx.Done():
				return
			case msg, ok := <-clientchan:
				if !ok {
					return
				}

				// SSE writing protocol:
				// Each data line must be prefixed with "data: "
				fmt.Fprintf(w, "event: %s\n", msg.Event)
				scanner := bufio.NewScanner(strings.NewReader(msg.Data))
				for scanner.Scan() {
					fmt.Fprintf(w, "data: %s\n", scanner.Text())
				}
				fmt.Fprint(w, "\n\n")

				flusher.Flush()
			}
		}
	}
}
