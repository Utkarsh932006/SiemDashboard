package parser

import "time"

const (
	SeverityCritical = "CRITICAL"
	SeverityHigh     = "HIGH"
	SeverityMedium   = "MEDIUM"
	SeverityLow      = "LOW"
	SeverityInfo     = "INFO"
)

type Event struct {
	Timestamp   time.Time `json:"timestamp"`
	SourceIP    string    `json:"source_ip"`
	Destination string    `json:"destination_ip,omitempty"`
	Host        string    `json:"host"`
	Program     string    `json:"program"`  //e.g "sshd", "sudo", "nginx"
	Facility    string    `json:"facility"` // e.g "auth", "daemon", "user"
	Severity    string    `json:"severity"`
	EventType   string    `json:"event_type"`
	Message     string    `json:"message"` // Clean log text
	Raw         string    `json:"raw"`
}
