package correlation

import "time"

type Rule struct {
	ID          string // Eg. "RULE_BRUTE_FORCE"
	Name        string // Eg. "SSH Brute Force Attack"
	EventType   string // Matches Event.EventType (eg. "AUTH_FAILURE")
	Threshold   int    // Number of events required to trigger the alert
	TimeWindow  time.Duration
	Severity    string
	Description string
}

type Alert struct {
	Timestamp  time.Time     `json:"timestamp"`
	RuleID     string        `json:"rule_id"`
	RuleName   string        `json:"rule_name"`
	Severity   string        `json:"severity"`
	SourceIP   string        `json:"source_ip"`
	Count      int           `json:"count"`
	TimeWindow time.Duration `json:"time_window"`
	Message    string        `json:"message"`
}

// DefaultRules returns the standard builtin security detection rules
func DefaultRules() []Rule {
	return []Rule{
		{
			ID:          "RULE_BRUTE_FORCE",
			Name:        "Brute Force Authentication Attack",
			EventType:   "AUTH_FAILURE",
			Threshold:   5,
			TimeWindow:  60 * time.Second,
			Severity:    "CRITICAL",
			Description: "5 failed authentication attempts from same IP within 60s",
		},
		{
			ID:          "RULE_PORT_SCAN",
			Name:        "Port Scan Activity",
			EventType:   "PORT_SCAN",
			Threshold:   10,
			TimeWindow:  30 * time.Second,
			Severity:    "HIGH",
			Description: "Multiple port scan probes detected within 30s",
		},
		{
			ID:          "RULE_RAPID_SUDO",
			Name:        "Suspicious Sudo Activity",
			EventType:   "SUDO_EXEC",
			Threshold:   3,
			TimeWindow:  15 * time.Second,
			Severity:    "HIGH",
			Description: "Multiple sudo privilege executions within 15s",
		},
	}
}
