package correlation

import (
	"testing"
	"time"

	"github.com/Utkarsh932006/SiemDashboard/internal/parser"
)

func TestEngineThresholdAndThrottle(t *testing.T) {
	rules := []Rule{
		{
			ID:         "RULE_TEST_BRUTE",
			Name:       "Test Brute Force",
			EventType:  "AUTH_FAILURE",
			Threshold:  3,
			TimeWindow: 10 * time.Second,
			Severity:   "CRITICAL",
		},
	}

	engine := NewEngine(rules)

	event := &parser.Event{
		Timestamp: time.Now(),
		SourceIP:  "192.168.1.99",
		EventType: "AUTH_FAILURE",
		Severity:  "HIGH",
		Message:   "Failed login attempt",
	}

	// 1st event: no alert
	if alerts := engine.Process(event); len(alerts) != 0 {
		t.Fatalf("expected 0 alerts, got %d", len(alerts))
	}

	// 2nd event: no alert
	if alerts := engine.Process(event); len(alerts) != 0 {
		t.Fatalf("expected 0 alerts, got %d", len(alerts))
	}

	// 3rd event: threshold reached, should alert
	alerts := engine.Process(event)
	if len(alerts) != 1 {
		t.Fatalf("expected 1 alert, got %d", len(alerts))
	}
	if alerts[0].RuleID != "RULE_TEST_BRUTE" {
		t.Errorf("expected RuleID 'RULE_TEST_BRUTE', got '%s'", alerts[0].RuleID)
	}

	// 4th event within window: should be throttled
	throttledAlerts := engine.Process(event)
	if len(throttledAlerts) != 0 {
		t.Errorf("expected alert to be throttled, but got %d alerts", len(throttledAlerts))
	}
}

func TestEngineUsesReceiptTimeInsteadOfSyslogTimestamp(t *testing.T) {
	engine := NewEngine([]Rule{{
		ID:         "RULE_TEST_RECEIPT_TIME",
		EventType:  "AUTH_FAILURE",
		Threshold:  2,
		TimeWindow: time.Minute,
		Severity:   "HIGH",
	}})

	// A sender can supply arbitrary and out-of-order timestamps. They must not
	// affect the live detection window or throttle state.
	if alerts := engine.Process(&parser.Event{
		Timestamp: time.Now().Add(24 * time.Hour),
		SourceIP:  "192.0.2.1",
		EventType: "AUTH_FAILURE",
	}); len(alerts) != 0 {
		t.Fatalf("expected no alert after first event, got %d", len(alerts))
	}

	alerts := engine.Process(&parser.Event{
		Timestamp: time.Now().Add(-24 * time.Hour),
		SourceIP:  "192.0.2.1",
		EventType: "AUTH_FAILURE",
	})
	if len(alerts) != 1 {
		t.Fatalf("expected one alert after second received event, got %d", len(alerts))
	}
	if time.Since(alerts[0].Timestamp) > time.Second {
		t.Fatalf("expected alert timestamp to use receipt time, got %s", alerts[0].Timestamp)
	}
}

func TestEnginePurgesInactiveSourceState(t *testing.T) {
	engine := NewEngine([]Rule{{
		ID:         "RULE_TEST_PURGE",
		EventType:  "AUTH_FAILURE",
		Threshold:  2,
		TimeWindow: time.Second,
	}})
	engine.maxWindow = time.Nanosecond
	engine.lastSeen["stale"] = time.Now().Add(-time.Second)
	engine.windows["stale"] = []time.Time{time.Now().Add(-time.Second)}
	engine.lastAlert["stale"] = time.Now().Add(-time.Second)

	engine.Process(&parser.Event{SourceIP: "192.0.2.2", EventType: "AUTH_FAILURE"})
	if _, ok := engine.lastSeen["stale"]; ok {
		t.Fatal("expected inactive correlation state to be purged")
	}
}
