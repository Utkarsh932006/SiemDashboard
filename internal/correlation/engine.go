package correlation

import (
	"fmt"
	"sync"
	"time"

	"github.com/Utkarsh932006/SiemDashboard/internal/parser"
)

type Engine struct {
	mu          sync.Mutex
	rules       []Rule
	windows     map[string][]time.Time // key: "ruleID:sourceIP" -> receipt timestamps
	lastAlert   map[string]time.Time   // key: "ruleID:sourceIP" -> last alert time (throttling)
	lastSeen    map[string]time.Time
	maxWindow   time.Duration
	nextCleanup time.Time
}

func NewEngine(rules []Rule) *Engine {
	maxWindow := time.Minute
	for _, rule := range rules {
		if rule.TimeWindow > maxWindow {
			maxWindow = rule.TimeWindow
		}
	}

	return &Engine{
		rules:     rules,
		windows:   make(map[string][]time.Time),
		lastAlert: make(map[string]time.Time),
		lastSeen:  make(map[string]time.Time),
		maxWindow: maxWindow,
	}
}

// Process analyzes any incoming events against all registered rules.
// Returns any triggered security alerts
func (e *Engine) Process(event *parser.Event) []*Alert {
	e.mu.Lock()
	defer e.mu.Unlock()

	var alerts []*Alert
	// Detection windows are based on receipt time, rather than sender-controlled
	// syslog timestamps. This keeps out-of-order and future-dated messages from
	// creating false positives or suppressing legitimate alerts.
	now := time.Now()
	if !e.nextCleanup.After(now) {
		e.purgeExpired(now)
		e.nextCleanup = now.Add(e.maxWindow)
	}

	for _, rule := range e.rules {
		if rule.EventType != event.EventType {
			continue
		}
		key := fmt.Sprintf("%s:%s", rule.ID, event.SourceIP)
		e.lastSeen[key] = now

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
			// Throttle: Do not alert repeatedly within the same time window
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

func (e *Engine) purgeExpired(now time.Time) {
	for key, seen := range e.lastSeen {
		if now.Sub(seen) > e.maxWindow {
			delete(e.windows, key)
			delete(e.lastAlert, key)
			delete(e.lastSeen, key)
		}
	}
}
