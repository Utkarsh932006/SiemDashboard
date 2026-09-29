package web

import (
	"fmt"
	"net/http"
)

func ServerSentEventHandler(hub *Hub) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "Streaming Not Supported", http.StatusInternalServerError)
			return
		}

		//Mandatory SSE http response headers
		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")

		// For nginx and stuff from bufferring the SSE events
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
				// User Closed the tab or exited the browser
				return
			case msg, ok := <-clientchan:
				if !ok {
					//channel closed by hub
					return
				}

				// SSE writing protocol format
				// event: <event_name>\n
				// data: <payload>\n\n
				fmt.Fprintf(w, "event: %s\ndata: %s\n\n", msg.Event, msg.Data)

				flusher.Flush()
			}
		}
	}
}
