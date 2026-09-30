// Standard Syslog (RFC 3163) encodes facility and severity in the PRI header:
//
// PRI = (Facility × 8) + Severity
// Severity = PRI (mod 8)
//
// This parser extracts PRI, identifies programs like sshd and sudo, extracts client IPs with regex, and assigns normalized event types.

package parser

import (
	"regexp"
	"strconv"
	"strings"
	"time"
)

var (
	// Matches RFC 3164 prefix: <PRI>MMM DD HH:MM:SS HOST PROGRAM[PID]: MESSAGE
	// Example: <34>Oct 11 22:14:15 server01 sshd[1234]: Failed password for root from 192.168.1.105
	syslogRegex = regexp.MustCompile(`^<(\d{1,3})>(?:([A-Z][a-z]{2}\s+\d+\s+\d{2}:\d{2}:\d{2})\s+)?([^\s:]+)?\s*([a-zA-Z0-9_\-]+)(?:\[\d+\])?:?\s*(.
  *)$`)

	// Regex to extract IP addresses from within log message bodies (e.g., "from 192.168.1.50")
	ipRegex = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)
)

var facilities = []string{
	"kernel", "user", "mail", "daemon", "auth", "syslog", "lpr", "news",
	"uucp", "cron", "authpriv", "ftp", "ntp", "security", "console", "solaris-cron",
	"local0", "local1", "local2", "local3", "local4", "local5", "local6", "local7",
}

func parse(raw string, remoteIP string) *Event {
	raw = strings.TrimSpace(raw)
	event := &Event{
		Timestamp: time.Now(),
		SourceIP:  remoteIP,
		Severity:  SeverityInfo,
		Facility:  "unknown",
		EventType: "GENERIC",
		Message:   raw,
		Raw:       raw,
	}

	matches := syslogRegex.FindStringSubmatch(raw)
	if len(matches) == 6 {
		priStr := matches[1]
		timeStr := matches[2]
		hostStr := matches[3]
		programStr := matches[4]
		msgStr := matches[5]

		// Decode PRI (Facility & Severity)
		if pri, err := strconv.Atoi(priStr); err == nil {
			fanCode := pri / 8
			sevCode := pri % 8

			if fanCode < len(facilities) {
				event.Facility = facilities[fanCode]
			}
			event.Severity = mapSyslogSeverity(sevCode)
		}

		// Parse Host and Program
		event.Host = hostStr
		event.Program = programStr
		event.Message = msgStr
		// timestamp is optional so try to parse timestamp only if it is present
		if timeStr != "" {
			// RFC 3164 time format doesn't have years; so we default to current year
			parsedTime, err := time.Parse("Jan _2 15:04:05", timeStr)
			if err == nil {
				now := time.Now()
				event.Timestamp = time.Date(now.Year(), parsedTime.Month(), parsedTime.Day(),
					parsedTime.Hour(), parsedTime.Minute(), parsedTime.Second(), 0, time.Local)
			}
		}
	}

	// Extract IP from within Message body if available
	if foundIP := ipRegex.FindString(event.Message); foundIP != "" {
		event.SourceIP = foundIP
	}

	// Categorize Event Type and set Severity
	classifySecurityEvent(event)

	return event
}

func mapSyslogSeverity(code int) string

func classifySecurityEvent(e *Event)
