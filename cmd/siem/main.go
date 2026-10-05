package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/Utkarsh932006/SiemDashboard/internal/correlation"
	"github.com/Utkarsh932006/SiemDashboard/internal/ingestion"
	"github.com/Utkarsh932006/SiemDashboard/internal/parser"
	"github.com/Utkarsh932006/SiemDashboard/internal/web"
)

func main() {
	// 1. Initialize real-time SSE Hub
	hub := web.NewHub()
	go hub.Run()

	// 2. Initialize Correlation Engine with default security rules
	engine := correlation.NewEngine(correlation.DefaultRules())

	// 3. Initialize Web Server
	server, err := web.NewServer(hub)
	if err != nil {
		log.Fatalf("failed to initialize web server: %v", err)
	}

	// 4. Start the UDP Syslog Receiver on port :5140
	receiver := ingestion.NewReciever(":5140", 1024)
	go func() {
		if err := receiver.Start(context.Background()); err != nil {
			log.Printf("UDP listener error: %v", err)
		}
	}()

	// 5. Ingestion & Correlation pipeline loop
	go func() {
		for raw := range receiver.Channel() {
			event := parser.Parse(raw.Data, raw.RemoteIP)
			fmt.Printf("Received [%s] %s from %s: %s\n", event.Severity, event.EventType, event.SourceIP, event.Message)

			// Process event through the Correlation Engine
			alerts := engine.Process(event)
			for _, alert := range alerts {
				fmt.Printf(" ALERT TRIGGERED: [%s] %s\n", alert.Severity, alert.Message)

				badgeClass := "badge-info"
				switch alert.Severity {
				case "CRITICAL":
					badgeClass = "badge-critical"
				case "HIGH":
					badgeClass = "badge-high"
				case "MEDIUM":
					badgeClass = "badge-medium"
				}

				rowHTML := fmt.Sprintf(
					`<tr class="new-row"><td>%s</td><td><span class="%s">%s</span></td><td><code>%s</code></td><td>%s</td><td>%s</td></tr>`,
					alert.Timestamp.Format("15:04:05"),
					badgeClass,
					alert.Severity,
					alert.SourceIP,
					alert.RuleID,
					alert.Message,
				)

				hub.Broadcast("alert", rowHTML)
			}
		}
	}()

	addr := ":3000"
	fmt.Printf(" SIEM Dashboard running on http://localhost%s\n", addr)
	fmt.Println(" Syslog UDP listener listening on :5140")
	if err := http.ListenAndServe(addr, server); err != nil {
		log.Fatalf("Server exited with error: %v", err)
	}
}
