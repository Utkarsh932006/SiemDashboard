package main

import (
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"time"

	"github.com/Utkarsh932006/SiemDashboard/internal/web"
)

func main() {
	hub := web.NewHub()
	go hub.Run()

	// Simulating a mock alert generator to check the correlation engine
	go simulateIncomingAlerts(hub)

	server, err := web.NewServer(hub)
	if err != nil {
		log.Fatalf("failed to initialize web server: %v", err)
	}

	addr := ":3000"
	fmt.Printf("Siem Dashboard running on http://localhost%s\n", addr)
	if err := http.ListenAndServe(addr, server); err != nil {
		log.Fatalf("Server exited wit error: %v", err)
	}
}

func simulateIncomingAlerts(hub *web.Hub) {
	severities := []struct {
		Level string
		Class string
	}{
		{"CRITICAL", "badge-critical"},
		{"HIGH", "badge-high"},
		{"MEDIUM", "badge-medium"},
		{"INFO", "badge-info"},
	}

	scenerios := []struct {
		Source    string
		EventType string
		Message   string
	}{
		{"192.168.1.105", "SSH_BRUTE_FORCE", "5 failed password attempts for root"},
		{"10.0.0.45", "PORT_SCAN", "Rapid SYN scan detected across 100 ports"},
		{"172.16.4.12", "SQL_INJECTION", "UNION SELECT detected in HTTP query param"},
		{"192.168.1.200", "PRIV_ESC", "Non-root user executed sudo without authorization"},
		{"10.0.0.88", "SUSPICIOUS_LOGIN", "Successful login outside buissness hours"},
	}

	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		sev := severities[rand.Intn(len(severities))]
		scen := scenerios[rand.Intn(len(scenerios))]
		timestamp := time.Now().Format("15:04:05")

		rowHTML := fmt.Sprintf(`
			<tr class="new-row">
				<td>%s</td>
				<td><span class="%s"> %s </span></td>
				<td><code>%s</code></td>
				<td>%s</td>
				<td>%s</td>
			</tr>`,
			timestamp,
			sev.Class,
			sev.Level,
			scen.Source,
			scen.EventType,
			scen.Message,
		)

		hub.Broadcast("alert", rowHTML)
	}
}
