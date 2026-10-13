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
