package main

import (
	"context"
	"fmt"
	"log"
	"net/http"

	"github.com/Utkarsh932006/SiemDashboard/internal/correlation"
	"github.com/Utkarsh932006/SiemDashboard/internal/ingestion"
	"github.com/Utkarsh932006/SiemDashboard/internal/parser"
	"github.com/Utkarsh932006/SiemDashboard/internal/storage"
	"github.com/Utkarsh932006/SiemDashboard/internal/web"
)

func main() {
	store, err := storage.New("siem.db")
	if err != nil {
		log.Fatalf("initializing storage: %v", err)
	}
	defer store.Close()

	hub := web.NewHub()
	go hub.Run()

	engine := correlation.NewEngine(correlation.DefaultRules())

	server, err := web.NewServer(hub, store)
	if err != nil {
		log.Fatalf("initializing web server: %v", err)
	}

	rawLogs := make(chan ingestion.RawLog, 2048)

	udpReceiver := ingestion.NewReceiver(":5140", 1024)
	go func() {
		if err := udpReceiver.Start(context.Background()); err != nil {
			log.Printf("UDP listener error: %v", err)
		}
	}()

	tcpReceiver := ingestion.NewTCPReceiver(":5140", 1024)
	go func() {
		if err := tcpReceiver.Start(context.Background()); err != nil {
			log.Printf("TCP listener error: %v", err)
		}
	}()

	go func() {
		for log := range udpReceiver.Channel() {
			rawLogs <- log
		}
	}()

	go func() {
		for log := range tcpReceiver.Channel() {
			rawLogs <- log
		}
	}()

	go func() {
		for raw := range rawLogs {
			event := parser.Parse(raw.Data, raw.RemoteIP)
			fmt.Printf("[%s] %s from %s: %s\n", event.Severity, event.EventType, event.SourceIP, event.Message)

			if err := store.InsertEvent(event); err != nil {
				log.Printf("persisting event: %v", err)
			}

			alerts := engine.Process(event)
			for _, alert := range alerts {
				fmt.Printf("[ALERT] [%s] %s\n", alert.Severity, alert.Message)

				if err := store.InsertAlert(alert); err != nil {
					log.Printf("persisting alert: %v", err)
				}

				hub.Broadcast("alert", web.FormatAlertHTML(alert))
			}
		}
	}()

	addr := ":3000"
	fmt.Printf("SIEM server listening on http://localhost%s\n", addr)
	fmt.Println("Syslog receiver listening on UDP/TCP :5140")
	fmt.Println("SQLite database active: siem.db")
	if err := http.ListenAndServe(addr, server); err != nil {
		log.Fatalf("server exited: %v", err)
	}
}
