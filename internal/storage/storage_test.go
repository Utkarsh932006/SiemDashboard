package storage

import (
	"os"
	"testing"
	"time"

	"github.com/Utkarsh932006/SiemDashboard/internal/correlation"
	"github.com/Utkarsh932006/SiemDashboard/internal/parser"
)

func TestStoreOperations(t *testing.T) {
	dbPath := "test_siem.db"
	defer os.Remove(dbPath)

	store, err := New(dbPath)
	if err != nil {
		t.Fatalf("failed to open database: %v", err)
	}
	defer store.Close()

	// Test event insertion
	event := &parser.Event{
		Timestamp: time.Now(),
		SourceIP:  "192.168.1.50",
		Program:   "sshd",
		Severity:  "HIGH",
		EventType: "AUTH_FAILURE",
		Message:   "test failed auth",
		Raw:       "<34>test raw",
	}
	if err := store.InsertEvent(event); err != nil {
		t.Fatalf("failed to insert event: %v", err)
	}

	// Test alert insertion
	alert := &correlation.Alert{
		Timestamp: time.Now(),
		RuleID:    "RULE_BRUTE_FORCE",
		RuleName:  "Brute Force",
		Severity:  "CRITICAL",
		SourceIP:  "192.168.1.50",
		Count:     5,
		Message:   "5 failed logins",
	}
	if err := store.InsertAlert(alert); err != nil {
		t.Fatalf("failed to insert alert: %v", err)
	}

	// Test querying alerts with filter
	alerts, err := store.QueryAlerts(EventFilter{Severity: "CRITICAL"})
	if err != nil {
		t.Fatalf("failed to query alerts: %v", err)
	}
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}

	// Test stats aggregation
	stats, err := store.GetStats()
	if err != nil {
		t.Fatalf("failed to get stats: %v", err)
	}
	if stats.Critical != 1 {
		t.Errorf("expected 1 critical alert in stats, got %d", stats.Critical)
	}
}
