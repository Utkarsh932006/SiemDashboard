package correlation

import (
	"fmt"
	"sync"
	"time"

	"github.com/Utkarsh932006/SiemDashboard/internal/parser"
)

type Engine struct {
	mu        sync.Mutex
	rules     []Rule
	windows   map[string][]time.Time // key: "ruleID:sourceIP" -> timestamps
	lastAlert map[string]time.Time   // key: "ruleID:sourceIP" -> last alert time (throttling)
}

func NewEngine(rules []Rule) *Engine {
	return &Engine{
		rules:     rules,
		windows:   make(map[string][]time.Time),
		lastAlert: make(map[string]time.Time),
	}
}

// Process analyzes any incoming events against all registered rules.
// Returns any triggered security alerts
func (e *Engine) Process(event *parser.Event) []*Alert {
	e.mu.Lock()
	defer e.mu.Unlock()

	var alerts []*Alert
	now := event.Timestamp

	for _, rule := range e.rules {
		if rule.EventType != event.EventType {
			continue
		}
		key := fmt.Sprintf("%s:%s", rule.ID, event.SourceIP)

		// Append current event timestamp
		e.windows[key] = append(e.windows[key], now)

		// Evict timestamps older than the sliding window
		cutoff := now.Add(-rule.TimeWindow)
		valid := e.windows[key][:0]
		for _, t := range e.windows[key] {
			if t.After(cutoff) {
				valid = append(valid, t)
			}
		}
		e.windows[key] = valid

		// Check if threshold is breached
		if len(valid) >= rule.Threshold {
			// Throttle: Don't alert repeadedly within same time window
			if last, exists := e.lastAlert[key]; exists && now.Sub(last) < rule.TimeWindow {
				continue
			}
			e.lastAlert[key] = now
			alerts = append(alerts, &Alert{
				Timestamp:  now,
				RuleID:     rule.ID,
				RuleName:   rule.Name,
				Severity:   rule.Severity,
				SourceIP:   event.SourceIP,
				Count:      len(valid),
				TimeWindow: rule.TimeWindow,
				Message:    fmt.Sprintf("%s (%d events detected from %s)", rule.Description, len(valid), event.SourceIP),
			})
		}
	}
	return alerts
}
